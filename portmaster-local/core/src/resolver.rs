use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use ureq::unversioned::resolver::Resolver as UreqResolver;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub end: usize,
}

fn read_u16(msg: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > msg.len() {
        return None;
    }
    Some(u16::from_be_bytes([msg[offset], msg[offset + 1]]))
}

pub fn parse_question(msg: &[u8]) -> Option<Question> {
    if msg.len() < 12 {
        return None;
    }
    let qdcount = read_u16(msg, 4)?;
    if qdcount == 0 {
        return None;
    }
    let mut offset = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        if offset >= msg.len() {
            return None;
        }
        let length = msg[offset];
        if length == 0 {
            offset += 1;
            break;
        }
        if length & 0xc0 != 0 {
            return None;
        }
        let length = length as usize;
        if length > 63 || offset + 1 + length > msg.len() {
            return None;
        }
        let label = String::from_utf8_lossy(&msg[offset + 1..offset + 1 + length]).to_string();
        labels.push(label);
        offset += 1 + length;
    }
    if labels.is_empty() {
        return None;
    }
    let name = labels.join(".").to_ascii_lowercase();
    if name.len() > 253 {
        return None;
    }
    let qtype = read_u16(msg, offset)?;
    if offset + 4 > msg.len() {
        return None;
    }
    offset += 4;
    Some(Question {
        name,
        qtype,
        end: offset,
    })
}

pub fn rewrite_id(response: &mut [u8], query: &[u8]) -> Result<(), String> {
    if response.len() < 12 || query.len() < 12 {
        return Err("DNS message too short".to_string());
    }
    response[0..2].copy_from_slice(&query[0..2]);
    Ok(())
}

pub fn blocked_response(query: &[u8], question_end: usize, rcode: u8) -> Vec<u8> {
    let mut response = query[..12].to_vec();
    let mut flags = u16::from_be_bytes([query[2], query[3]]);
    flags |= 0x8000; // QR
    flags |= 0x0080; // RA
    flags = (flags & !0x000f) | (rcode as u16 & 0x000f);
    response[2..4].copy_from_slice(&flags.to_be_bytes());
    response[4..6].copy_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    response[6..8].copy_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    response[8..10].copy_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response[10..12].copy_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    response.extend_from_slice(&query[12..question_end]);
    response
}

fn skip_name(msg: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        if offset >= msg.len() {
            return None;
        }
        let length = msg[offset];
        if length == 0 {
            return Some(offset + 1);
        }
        if length & 0xc0 == 0xc0 {
            if offset + 2 > msg.len() {
                return None;
            }
            return Some(offset + 2);
        }
        let length = length as usize;
        if length > 63 || offset + 1 + length > msg.len() {
            return None;
        }
        offset += 1 + length;
    }
}

/// Parse A/AAAA answer addresses from a DNS response.
pub fn answer_ips(msg: &[u8]) -> Vec<IpAddr> {
    let mut result = Vec::new();
    let Some(qd) = read_u16(msg, 4) else {
        return result;
    };
    let Some(an) = read_u16(msg, 6) else {
        return result;
    };
    let mut offset = 12usize;
    for _ in 0..qd {
        offset = match skip_name(msg, offset) {
            Some(next) => next,
            None => return result,
        };
        offset += 4;
        if offset > msg.len() {
            return result;
        }
    }
    for _ in 0..an {
        offset = match skip_name(msg, offset) {
            Some(next) => next,
            None => return result,
        };
        if offset + 10 > msg.len() {
            return result;
        }
        let rtype = match read_u16(msg, offset) {
            Some(value) => value,
            None => return result,
        };
        // Skip class (2), ttl (4), rdlength (2).
        let rdlength = match read_u16(msg, offset + 8) {
            Some(value) => value as usize,
            None => return result,
        };
        let rdata_start = offset + 10;
        if rdata_start + rdlength > msg.len() {
            return result;
        }
        if rtype == 1 && rdlength == 4 {
            let octets = &msg[rdata_start..rdata_start + 4];
            result.push(IpAddr::V4(Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            )));
        } else if rtype == 28 && rdlength == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&msg[rdata_start..rdata_start + 16]);
            result.push(IpAddr::V6(Ipv6Addr::from(octets)));
        }
        offset = rdata_start + rdlength;
    }
    result
}

/// Build one DNS query message. Kept public so the engine can probe upstream
/// reachability without using the operating system resolver.
pub fn build_query(name: &str, qtype: u16, id: u16) -> Result<Vec<u8>, String> {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() {
        return Err("DNS name is required".to_string());
    }
    if name.len() > 253 {
        return Err("DNS name is too long".to_string());
    }
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    message.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err("DNS name has an empty or oversized label".to_string());
        }
        message.push(bytes.len() as u8);
        message.extend_from_slice(bytes);
    }
    message.push(0);
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes()); // IN class
    Ok(message)
}

fn random_query_id() -> u16 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| (duration.as_nanos() ^ (std::process::id() as u128)) as u16)
        .unwrap_or(0x3a4b)
}

fn validate_response(response: &[u8], query: &[u8]) -> Result<(), String> {
    if response.len() < 12 {
        return Err("DNS response is too short".to_string());
    }
    if response[0..2] != query[0..2] {
        return Err("DNS response id does not match the query".to_string());
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 {
        return Err("DNS response is not marked as a response".to_string());
    }
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(format!("DNS server returned rcode {rcode}"));
    }
    Ok(())
}

/// Send a raw DNS query to one server over UDP. The server address is explicit,
/// so this path never consults the operating system resolver.
pub fn query_dns_server(
    server: SocketAddr,
    name: &str,
    qtype: u16,
    timeout_ms: u32,
) -> Result<Vec<IpAddr>, String> {
    let query = build_query(name, qtype, random_query_id())?;
    let bind_addr: SocketAddr = if server.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind_addr)
        .map_err(|err| format!("could not bind bootstrap DNS socket: {err}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(timeout_ms as u64)))
        .map_err(|err| format!("could not set bootstrap DNS timeout: {err}"))?;
    socket
        .send_to(&query, server)
        .map_err(|err| format!("could not send DNS query to {server}: {err}"))?;

    let mut buffer = [0u8; 4096];
    let (length, _) = socket
        .recv_from(&mut buffer)
        .map_err(|err| format!("DNS query to {server} failed: {err}"))?;
    let response = &buffer[..length];
    validate_response(response, &query)?;

    if u16::from_be_bytes([response[2], response[3]]) & 0x0200 != 0 {
        return query_dns_server_tcp(server, &query, timeout_ms);
    }

    let ips = answer_ips(response);
    if ips.is_empty() {
        return Err(format!("DNS server {server} returned no addresses"));
    }
    Ok(ips)
}

fn query_dns_server_tcp(
    server: SocketAddr,
    query: &[u8],
    timeout_ms: u32,
) -> Result<Vec<IpAddr>, String> {
    let timeout = Duration::from_millis(timeout_ms as u64);
    let mut stream = TcpStream::connect_timeout(&server, timeout)
        .map_err(|err| format!("could not connect to DNS server {server} over TCP: {err}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("could not set DNS TCP timeout: {err}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| format!("could not set DNS TCP timeout: {err}"))?;

    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(query);
    std::io::Write::write_all(&mut stream, &framed)
        .map_err(|err| format!("could not write DNS TCP query: {err}"))?;

    let mut length_bytes = [0u8; 2];
    std::io::Read::read_exact(&mut stream, &mut length_bytes)
        .map_err(|err| format!("could not read DNS TCP response length: {err}"))?;
    let length = u16::from_be_bytes(length_bytes) as usize;
    if length < 12 || length > 65535 {
        return Err("DNS TCP response length is invalid".to_string());
    }
    let mut response = vec![0u8; length];
    std::io::Read::read_exact(&mut stream, &mut response)
        .map_err(|err| format!("could not read DNS TCP response: {err}"))?;
    validate_response(&response, query)?;
    let ips = answer_ips(&response);
    if ips.is_empty() {
        return Err(format!("DNS server {server} returned no addresses over TCP"));
    }
    Ok(ips)
}

/// Resolve one host through explicit bootstrap DNS servers, bypassing the OS
/// resolver. This is the critical fix for the self-referential DNS loop that
/// occurs when the OS resolver points at the local Portmaster listener.
pub fn bootstrap_resolve(
    host: &str,
    servers: &[IpAddr],
    timeout_ms: u32,
) -> Result<Vec<IpAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    let mut found = Vec::new();
    let mut last_error = String::new();
    for server in servers {
        if server.is_loopback() || server.is_unspecified() {
            continue;
        }
        for qtype in [1u16, 28u16] {
            let endpoint = SocketAddr::new(*server, 53);
            match query_dns_server(endpoint, host, qtype, timeout_ms) {
                Ok(ips) => {
                    for ip in ips {
                        if !found.contains(&ip) {
                            found.push(ip);
                        }
                    }
                }
                Err(err) => last_error = err,
            }
        }
        if !found.is_empty() {
            return Ok(found);
        }
    }
    if last_error.is_empty() {
        last_error = "no bootstrap DNS server is available".to_string();
    }
    Err(format!("bootstrap resolution failed for {host}: {last_error}"))
}

/// ureq resolver backed by explicit bootstrap DNS servers. If no bootstrap
/// server is configured it falls back to the normal OS resolver, which is safe
/// when the OS DNS is not pointed at this app.
#[derive(Clone, Debug, Default)]
pub struct BootstrapResolver {
    servers: Vec<IpAddr>,
}

impl BootstrapResolver {
    pub fn new(servers: Vec<IpAddr>) -> Self {
        Self { servers }
    }
}

impl UreqResolver for BootstrapResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let Some(scheme) = uri.scheme() else {
            return Err(ureq::Error::HostNotFound);
        };
        let Some(authority) = uri.authority() else {
            return Err(ureq::Error::HostNotFound);
        };
        let Some(host_and_port) =
            ureq::unversioned::resolver::DefaultResolver::host_and_port(scheme, authority)
        else {
            return Err(ureq::Error::HostNotFound);
        };
        let Some((host, port_text)) = host_and_port.rsplit_once(':') else {
            return Err(ureq::Error::HostNotFound);
        };
        let port = port_text.parse::<u16>().unwrap_or(443);

        let budget = *timeout.after;
        let timeout_ms = budget.as_millis().min(4000) as u32;
        let timeout_ms = timeout_ms.max(500);

        let ips = if self.servers.is_empty() {
            ureq::unversioned::resolver::DefaultResolver::default()
                .resolve(uri, config, timeout)
                .map(|addrs| addrs.iter().map(|addr| addr.ip()).collect::<Vec<IpAddr>>())?
        } else {
            bootstrap_resolve(host, &self.servers, timeout_ms)
                .map_err(|_| ureq::Error::HostNotFound)?
        };

        let mut result = self.empty();
        for ip in ips {
            let address = SocketAddr::new(ip, port);
            if config.ip_family().keep_wanted(std::iter::once(address)).next().is_some() {
                result.push(address);
            }
        }
        if result.len() == 0 {
            Err(ureq::Error::HostNotFound)
        } else {
            Ok(result)
        }
    }
}

pub const DEFAULT_HTTP_TIMEOUT_MS: u32 = 10_000;
pub const DEFAULT_MAX_HTTP_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpOptions {
    pub timeout_ms: u32,
    pub max_bytes: usize,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_HTTP_TIMEOUT_MS,
            max_bytes: DEFAULT_MAX_HTTP_BYTES,
        }
    }
}

impl HttpOptions {
    pub fn new(timeout_ms: u32, max_bytes: usize) -> Self {
        Self {
            timeout_ms,
            max_bytes,
        }
    }
}

fn validate_http_options(options: HttpOptions) -> Result<(), String> {
    if options.timeout_ms == 0 {
        return Err("HTTP timeout must be greater than zero".to_string());
    }
    if options.max_bytes == 0 {
        return Err("HTTP size limit must be greater than zero".to_string());
    }
    Ok(())
}

fn build_agent(options: HttpOptions, servers: &[IpAddr]) -> Result<ureq::Agent, String> {
    validate_http_options(options)?;
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::NativeTls)
        .build();
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_millis(options.timeout_ms as u64)))
        .http_status_as_error(false)
        .tls_config(tls)
        .build();
    Ok(ureq::Agent::with_parts(
        config,
        ureq::unversioned::transport::DefaultConnector::default(),
        BootstrapResolver::new(servers.to_vec()),
    ))
}

pub fn http_get(url: &str) -> Result<Vec<u8>, String> {
    http_get_with(url, HttpOptions::default())
}

pub fn http_get_with(url: &str, options: HttpOptions) -> Result<Vec<u8>, String> {
    http_get_with_servers(url, options, &[])
}

/// Fetch HTTPS content using explicit bootstrap DNS servers, so filter downloads
/// keep working while the OS resolver points at this app's own listener.
pub fn http_get_with_servers(
    url: &str,
    options: HttpOptions,
    servers: &[IpAddr],
) -> Result<Vec<u8>, String> {
    let agent = build_agent(options, servers)?;
    let mut response = agent
        .get(url)
        .header("Accept", "text/plain, application/octet-stream")
        .header("User-Agent", "PortmasterLocal/0.1")
        .call()
        .map_err(|err| format!("HTTP request failed for {url}: {err}"))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {status} for {url}"));
    }
    response
        .body_mut()
        .with_config()
        .limit(options.max_bytes as u64)
        .read_to_vec()
        .map_err(|err| format!("read HTTP response from {url}: {err}"))
}

pub fn doh_post(url: &str, query: &[u8]) -> Result<Vec<u8>, String> {
    doh_post_with_servers(url, query, &[])
}

/// DoH POST over ureq/rustls with bootstrap resolution. The old WinHTTP path
/// resolved DoH hostnames through the OS resolver, which is the deployment
/// failure this replaces.
pub fn doh_post_with_servers(
    url: &str,
    query: &[u8],
    servers: &[IpAddr],
) -> Result<Vec<u8>, String> {
    let options = HttpOptions::default();
    let agent = build_agent(options, servers)?;
    let mut response = agent
        .post(url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .header("User-Agent", "PortmasterLocal/0.1")
        .send(query)
        .map_err(|err| format!("DoH request failed for {url}: {err}"))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(format!("DoH HTTP {status} for {url}"));
    }
    let response_bytes = response
        .body_mut()
        .with_config()
        .limit(options.max_bytes as u64)
        .read_to_vec()
        .map_err(|err| format!("read DoH response from {url}: {err}"))?;
    if response_bytes.len() < 12 {
        return Err("DoH response is not a DNS message".to_string());
    }
    Ok(response_bytes)
}

/// Forward a raw DNS query to an explicit upstream server over UDP. This is a
/// last-resort path so internet resolution survives if DoH endpoints are
/// unreachable; it never consults the OS resolver.
fn forward_to_endpoint(
    query: &[u8],
    endpoint: SocketAddr,
    timeout_ms: u32,
) -> Result<Vec<u8>, String> {
    let bind_addr: SocketAddr = if endpoint.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket =
        UdpSocket::bind(bind_addr).map_err(|err| format!("could not bind forwarding socket: {err}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(timeout_ms as u64)))
        .map_err(|err| format!("could not set forwarding timeout: {err}"))?;
    socket
        .send_to(query, endpoint)
        .map_err(|err| format!("could not send to {endpoint}: {err}"))?;

    let mut buffer = [0u8; 4096];
    let (length, _) = socket
        .recv_from(&mut buffer)
        .map_err(|err| format!("forwarding to {endpoint} failed: {err}"))?;
    let response = buffer[..length].to_vec();
    if response.len() < 12 || response[0..2] != query[0..2] {
        return Err(format!("invalid response from {endpoint}"));
    }
    Ok(response)
}

pub fn plain_dns_forward(
    query: &[u8],
    servers: &[IpAddr],
    timeout_ms: u32,
) -> Result<Vec<u8>, String> {
    if query.len() < 12 {
        return Err("DNS query is too short".to_string());
    }
    let mut last_error = "no recorded upstream DNS server".to_string();
    for server in servers {
        if server.is_unspecified() {
            continue;
        }
        match forward_to_endpoint(query, SocketAddr::new(*server, 53), timeout_ms) {
            Ok(response) => return Ok(response),
            Err(err) => last_error = err,
        }
    }
    Err(last_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut msg = vec![0u8; 12];
        msg[0] = 0x12;
        msg[1] = 0x34;
        msg[2] = 0x01; // RD
        msg[4] = 0x00;
        msg[5] = 0x01;
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg
    }

    #[test]
    fn parses_dns_question() {
        let query = make_query("ads.example.com", 1);
        let question = parse_question(&query).unwrap();
        assert_eq!(question.name, "ads.example.com");
        assert_eq!(question.qtype, 1);
        assert_eq!(question.end, query.len());
    }

    #[test]
    fn builds_nxdomain_response_with_question() {
        let query = make_query("blocked.example", 1);
        let question = parse_question(&query).unwrap();
        let response = blocked_response(&query, question.end, 3);
        assert_eq!(&response[0..2], &query[0..2]);
        assert_eq!(u16::from_be_bytes([response[4], response[5]]), 1);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(
            u16::from_be_bytes([response[2], response[3]]) & 0x000f,
            3
        );
        assert_eq!(response.len(), 12 + (question.end - 12));
    }

    #[test]
    fn reads_a_and_aaaa_answers() {
        let query = make_query("example.com", 1);
        let mut response = query.clone();
        response[2] |= 0x80; // QR
        response[6] = 0x00;
        response[7] = 0x02;
        response[10] = 0;
        response[11] = 0;
        // Answer 1: pointer to question name, type A, class IN, ttl 60, length 4
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&[192, 0, 2, 1]);
        // Answer 2: pointer, type AAAA, class IN, ttl 60, length 16
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&28u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&16u16.to_be_bytes());
        response.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let ips = answer_ips(&response);
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(ips[1], "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn build_query_encodes_name_type_and_id() {
        let query = build_query("example.com", 28, 0x1234).unwrap();
        assert_eq!(u16::from_be_bytes([query[0], query[1]]), 0x1234);
        assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1);
        let question = parse_question(&query).unwrap();
        assert_eq!(question.name, "example.com");
        assert_eq!(question.qtype, 28);
        assert!(build_query("", 1, 1).is_err());
        assert!(build_query("a..b", 1, 1).is_err());
    }

    #[test]
    fn bootstrap_resolve_accepts_a_literal_ip_without_querying_dns() {
        let ips = bootstrap_resolve("1.1.1.1", &[], 1000).unwrap();
        assert_eq!(ips, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn query_dns_server_parses_a_mock_udp_answer() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut buffer = [0u8; 512];
            let (length, peer) = server.recv_from(&mut buffer).unwrap();
            let query = buffer[..length].to_vec();
            let mut response = query[..12].to_vec();
            response[2] |= 0x80; // QR
            response[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT
            response.extend_from_slice(&query[12..]);
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&60u32.to_be_bytes());
            response.extend_from_slice(&4u16.to_be_bytes());
            response.extend_from_slice(&[192, 0, 2, 9]);
            server.send_to(&response, peer).unwrap();
        });
        let ips = query_dns_server(server_addr, "example.com", 1, 2000).unwrap();
        handle.join().unwrap();
        assert_eq!(ips, vec!["192.0.2.9".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn plain_forward_returns_a_mock_response_with_the_same_id() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut buffer = [0u8; 512];
            let (length, peer) = server.recv_from(&mut buffer).unwrap();
            let query = buffer[..length].to_vec();
            let mut response = query.clone();
            response[2] |= 0x80;
            response[6..12].copy_from_slice(&[0u8; 6]);
            server.send_to(&response, peer).unwrap();
        });
        let query = build_query("example.com", 1, 0x4242).unwrap();
        let response = forward_to_endpoint(&query, server_addr, 2000).unwrap();
        handle.join().unwrap();
        assert_eq!(&response[0..2], &query[0..2]);
    }

    #[test]
    fn http_options_have_safe_defaults() {
        let options = HttpOptions::default();
        assert_eq!(options.timeout_ms, DEFAULT_HTTP_TIMEOUT_MS);
        assert_eq!(options.max_bytes, DEFAULT_MAX_HTTP_BYTES);
        assert!(validate_http_options(options).is_ok());
    }

    #[test]
    fn http_options_reject_zero_values() {
        assert!(validate_http_options(HttpOptions::new(0, 1024)).is_err());
        assert!(validate_http_options(HttpOptions::new(1000, 0)).is_err());
    }
}
