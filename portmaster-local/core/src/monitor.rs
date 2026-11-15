use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Connection {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub pid: u32,
    pub process: String,
    pub path: String,
    pub state: String,
    pub bytes_out: Option<u64>,
    pub bytes_in: Option<u64>,
}

pub fn snapshot() -> Vec<Connection> {
    #[cfg(windows)]
    {
        windows_impl::snapshot()
    }
    #[cfg(target_os = "linux")]
    {
        linux_impl::snapshot()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Vec::new()
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::{Connection, ProcessInfo};
    use std::ffi::c_void;
    use std::net::Ipv4Addr;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, GetPerTcpConnectionEStats,
        SetPerTcpConnectionEStats, TCP_ESTATS_DATA_RW_v0, TCP_ESTATS_DATA_ROD_v0,
        TCP_TABLE_OWNER_PID_ALL, TcpConnectionEstatsData, UDP_TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_LH,
        MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const AF_INET: u32 = 2;

    fn tcp_table() -> Result<Vec<MIB_TCPROW_OWNER_PID>, String> {
        let mut size: u32 = 0;
        let rc = unsafe {
            GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc != ERROR_INSUFFICIENT_BUFFER.0 && rc != 0 {
            return Err(format!("GetExtendedTcpTable sizing failed: {rc}"));
        }
        let words = ((size as usize) + 7) / 8;
        let mut buffer = vec![0u64; words.max(1)];
        let mut actual = size;
        let rc = unsafe {
            GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut c_void),
                &mut actual,
                false,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc != 0 {
            return Err(format!("GetExtendedTcpTable failed: {rc}"));
        }
        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let count = table.dwNumEntries as usize;
        let mut rows = Vec::with_capacity(count);
        for index in 0..count {
            rows.push(unsafe { *table.table.as_ptr().add(index) });
        }
        Ok(rows)
    }

    fn udp_table() -> Result<Vec<MIB_UDPROW_OWNER_PID>, String> {
        let mut size: u32 = 0;
        let rc = unsafe {
            GetExtendedUdpTable(None, &mut size, false, AF_INET, UDP_TABLE_OWNER_PID, 0)
        };
        if rc != ERROR_INSUFFICIENT_BUFFER.0 && rc != 0 {
            return Err(format!("GetExtendedUdpTable sizing failed: {rc}"));
        }
        let words = ((size as usize) + 7) / 8;
        let mut buffer = vec![0u64; words.max(1)];
        let mut actual = size;
        let rc = unsafe {
            GetExtendedUdpTable(
                Some(buffer.as_mut_ptr() as *mut c_void),
                &mut actual,
                false,
                AF_INET,
                UDP_TABLE_OWNER_PID,
                0,
            )
        };
        if rc != 0 {
            return Err(format!("GetExtendedUdpTable failed: {rc}"));
        }
        let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let count = table.dwNumEntries as usize;
        let mut rows = Vec::with_capacity(count);
        for index in 0..count {
            rows.push(unsafe { *table.table.as_ptr().add(index) });
        }
        Ok(rows)
    }

    fn process_for_pid(pid: u32) -> ProcessInfo {
        let mut info = ProcessInfo {
            pid,
            name: format!("pid:{pid}"),
            path: String::new(),
        };
        let handle: HANDLE = match unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
        } {
            Ok(handle) => handle,
            Err(_) => return info,
        };
        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;
        let result = unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut size,
            )
        };
        let _ = unsafe { CloseHandle(handle) };
        if result.is_ok() && size > 0 {
            let path = String::from_utf16_lossy(&buffer[..size as usize]);
            info.name = path
                .rsplit('\\')
                .next()
                .unwrap_or(&path)
                .to_string();
            info.path = path;
        }
        info
    }

    fn network_port(value: u32) -> u16 {
        u16::from_be((value & 0xffff) as u16)
    }

    fn network_ip(value: u32) -> Ipv4Addr {
        Ipv4Addr::from(value.to_be())
    }

    fn tcp_state(state: u32) -> &'static str {
        match state {
            1 => "ESTABLISHED",
            2 => "SYN_SENT",
            3 => "SYN_RECV",
            4 => "FIN_WAIT1",
            5 => "FIN_WAIT2",
            6 => "TIME_WAIT",
            7 => "CLOSE",
            8 => "CLOSE_WAIT",
            9 => "LAST_ACK",
            10 => "LISTEN",
            11 => "CLOSING",
            12 => "DELETE_TCB",
            _ => "UNKNOWN",
        }
    }

    fn tcp_bytes(row: &MIB_TCPROW_OWNER_PID) -> Option<(u64, u64)> {
        let row_ptr = row as *const MIB_TCPROW_OWNER_PID as *const MIB_TCPROW_LH;
        let mut rw = TCP_ESTATS_DATA_RW_v0 {
            EnableCollection: true,
        };
        let rw_bytes = unsafe {
            std::slice::from_raw_parts_mut(
                &mut rw as *mut TCP_ESTATS_DATA_RW_v0 as *mut u8,
                std::mem::size_of::<TCP_ESTATS_DATA_RW_v0>(),
            )
        };
        let _ = unsafe {
            SetPerTcpConnectionEStats(row_ptr, TcpConnectionEstatsData, rw_bytes, 0, 0)
        };
        let mut rod = TCP_ESTATS_DATA_ROD_v0::default();
        let rod_bytes = unsafe {
            std::slice::from_raw_parts_mut(
                &mut rod as *mut TCP_ESTATS_DATA_ROD_v0 as *mut u8,
                std::mem::size_of::<TCP_ESTATS_DATA_ROD_v0>(),
            )
        };
        let rc = unsafe {
            GetPerTcpConnectionEStats(
                row_ptr,
                TcpConnectionEstatsData,
                None,
                0,
                None,
                0,
                Some(rod_bytes),
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        Some((rod.DataBytesOut, rod.DataBytesIn))
    }

    pub fn snapshot() -> Vec<Connection> {
        let mut connections = Vec::new();
        if let Ok(rows) = tcp_table() {
            for row in rows {
                let state = tcp_state(row.dwState);
                let remote_port = network_port(row.dwRemotePort);
                if state == "LISTEN" || remote_port == 0 {
                    continue;
                }
                let process = process_for_pid(row.dwOwningPid);
                let (bytes_out, bytes_in) = tcp_bytes(&row).unwrap_or((0, 0));
                connections.push(Connection {
                    protocol: "tcp".to_string(),
                    local_addr: network_ip(row.dwLocalAddr).to_string(),
                    local_port: network_port(row.dwLocalPort),
                    remote_addr: network_ip(row.dwRemoteAddr).to_string(),
                    remote_port,
                    pid: row.dwOwningPid,
                    process: process.name,
                    path: process.path,
                    state: state.to_string(),
                    bytes_out: Some(bytes_out),
                    bytes_in: Some(bytes_in),
                });
            }
        }
        if let Ok(rows) = udp_table() {
            for row in rows {
                if row.dwOwningPid == 0 {
                    continue;
                }
                let process = process_for_pid(row.dwOwningPid);
                connections.push(Connection {
                    protocol: "udp".to_string(),
                    local_addr: network_ip(row.dwLocalAddr).to_string(),
                    local_port: network_port(row.dwLocalPort),
                    remote_addr: String::new(),
                    remote_port: 0,
                    pid: row.dwOwningPid,
                    process: process.name,
                    path: process.path,
                    state: "UDP".to_string(),
                    bytes_out: None,
                    bytes_in: None,
                });
            }
        }
        connections.sort_by(|a, b| {
            b.pid
                .cmp(&a.pid)
                .then_with(|| a.protocol.cmp(&b.protocol))
                .then_with(|| a.local_port.cmp(&b.local_port))
        });
        connections
    }
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::{Connection, ProcessInfo};
    use std::collections::HashMap;
    use std::fs;
    use std::net::Ipv4Addr;

    fn parse_ipv4_hex(value: &str) -> Option<Ipv4Addr> {
        let raw = u32::from_str_radix(value, 16).ok()?;
        Some(Ipv4Addr::from(raw.to_le_bytes()))
    }

    fn parse_endpoint(value: &str) -> Option<(Ipv4Addr, u16)> {
        let (addr, port) = value.split_once(':')?;
        Some((parse_ipv4_hex(addr)?, u16::from_str_radix(port, 16).ok()?))
    }

    fn state_name(code: &str) -> &'static str {
        match code {
            "01" => "ESTABLISHED",
            "02" => "SYN_SENT",
            "03" => "SYN_RECV",
            "04" => "FIN_WAIT1",
            "05" => "FIN_WAIT2",
            "06" => "TIME_WAIT",
            "07" => "CLOSE",
            "08" => "CLOSE_WAIT",
            "09" => "LAST_ACK",
            "0A" => "LISTEN",
            "0B" => "CLOSING",
            _ => "UNKNOWN",
        }
    }

    fn process_info(pid: u32) -> ProcessInfo {
        let name = fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| format!("pid:{pid}"));
        let path = fs::read_link(format!("/proc/{pid}/exe"))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        ProcessInfo { pid, name, path }
    }

    fn socket_inode_to_pid() -> HashMap<u64, ProcessInfo> {
        let mut map = HashMap::new();
        let proc_dir = match fs::read_dir("/proc") {
            Ok(dir) => dir,
            Err(_) => return map,
        };
        for entry in proc_dir.flatten() {
            let pid_text = entry.file_name().to_string_lossy().to_string();
            let pid: u32 = match pid_text.parse() {
                Ok(pid) => pid,
                Err(_) => continue,
            };
            let fd_dir = match fs::read_dir(format!("/proc/{pid}/fd")) {
                Ok(dir) => dir,
                Err(_) => continue,
            };
            for fd in fd_dir.flatten() {
                let target = match fs::read_link(fd.path()) {
                    Ok(target) => target,
                    Err(_) => continue,
                };
                let target_text = target.to_string_lossy();
                if let Some(inode_text) = target_text
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                {
                    if let Ok(inode) = inode_text.parse::<u64>() {
                        map.entry(inode).or_insert_with(|| process_info(pid));
                    }
                }
            }
        }
        map
    }

    fn parse_table(path: &str, protocol: &str, inode_map: &HashMap<u64, ProcessInfo>) -> Vec<Connection> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(_) => return Vec::new(),
        };
        let mut connections = Vec::new();
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let (local_addr, local_port) = match parse_endpoint(fields[1]) {
                Some(endpoint) => endpoint,
                None => continue,
            };
            let (remote_addr, remote_port) = match parse_endpoint(fields[2]) {
                Some(endpoint) => endpoint,
                None => continue,
            };
            let state = state_name(fields[3]);
            if protocol == "tcp" && (state == "LISTEN" || remote_port == 0) {
                continue;
            }
            let inode = fields[9].parse::<u64>().unwrap_or(0);
            let process = inode_map
                .get(&inode)
                .cloned()
                .unwrap_or(ProcessInfo {
                    pid: 0,
                    name: "unknown".to_string(),
                    path: String::new(),
                });
            connections.push(Connection {
                protocol: protocol.to_string(),
                local_addr: local_addr.to_string(),
                local_port,
                remote_addr: remote_addr.to_string(),
                remote_port,
                pid: process.pid,
                process: process.name,
                path: process.path,
                state: state.to_string(),
                bytes_out: None,
                bytes_in: None,
            });
        }
        connections
    }

    pub fn snapshot() -> Vec<Connection> {
        let inode_map = socket_inode_to_pid();
        let mut connections = parse_table("/proc/net/tcp", "tcp", &inode_map);
        connections.extend(parse_table("/proc/net/udp", "udp", &inode_map));
        connections.sort_by(|a, b| {
            b.pid
                .cmp(&a.pid)
                .then_with(|| a.protocol.cmp(&b.protocol))
                .then_with(|| a.local_port.cmp(&b.local_port))
        });
        connections
    }
}
