const tauri = window.__TAURI__ && window.__TAURI__.core ? window.__TAURI__.core : null;
const invoke = tauri ? tauri.invoke : null;

const $ = (id) => document.getElementById(id);
let snapshot = null;
let activeTab = "overview";
let settingsDirty = false;
let settingsLoaded = false;

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function setStatus(text, error = false) {
  const el = $("status");
  el.textContent = text;
  el.classList.toggle("is-error", error);
}

function fmtBytes(value) {
  if (value === null || value === undefined) return "—";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
  return `${(value / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function listenerSummary() {
  const listeners = [];
  if (snapshot.dns_udp_port) listeners.push(`UDP ${snapshot.dns_udp_port}`);
  if (snapshot.dns_tcp_port) listeners.push(`TCP ${snapshot.dns_tcp_port}`);
  return listeners.join(" · ");
}

function conflictSummary() {
  if (!snapshot.port_conflicts.length) return "No port conflicts.";
  return "Port conflicts: " + snapshot.port_conflicts
    .map((conflict) => `${conflict.protocol.toUpperCase()} ${conflict.port} (${conflict.reason})`)
    .join("; ");
}

async function refresh() {
  if (!invoke) return;
  try {
    snapshot = await invoke("get_snapshot");
    render();
    if (snapshot.dns_running) {
      let text = `Connected · ${snapshot.platform} · DNS ${snapshot.settings.bind_addr} · ${listenerSummary()}`;
      if (snapshot.port_conflicts.length) text += " · port conflict(s)";
      setStatus(text, snapshot.port_conflicts.length > 0);
    } else if (snapshot.dns_error) {
      setStatus(`Connected · DNS failed: ${snapshot.dns_error}`, true);
    } else {
      setStatus("Connected · DNS server is not running");
    }
  } catch (err) {
    setStatus(`Bridge error: ${err}`, true);
  }
}

async function action(name, args, message) {
  try {
    await invoke(name, args || {});
    if (message) setStatus(message);
    await refresh();
  } catch (err) {
    setStatus(`Error: ${err}`, true);
  }
}

function renderUpdate() {
  const el = $("update-status");
  const total = snapshot.update_total || 0;
  const done = snapshot.update_completed || 0;
  if (snapshot.update_running) {
    let text = total ? `Updating filter lists: ${done}/${total}` : "Updating filter lists…";
    if (snapshot.update_current) text += ` · ${snapshot.update_current}`;
    el.textContent = text;
  } else {
    el.textContent = total ? `Filter update finished: ${total} list(s) processed.` : "No filter update running.";
  }
  $("update").disabled = snapshot.update_running;
  $("download-all").disabled = snapshot.update_running;
}

function render() {
  if (!snapshot) return;
  const stats = snapshot.stats;

  renderUpdate();

  $("stat-queries").textContent = stats.queries.toLocaleString();
  $("stat-blocked").textContent = stats.blocked.toLocaleString();
  $("stat-forwarded").textContent = stats.forwarded.toLocaleString();
  $("stat-blocked-ips").textContent = stats.blocked_ips.toLocaleString();
  $("stat-domains").textContent = snapshot.domain_count.toLocaleString();
  $("dns-udp").textContent = snapshot.dns_udp_port || "offline";
  $("dns-tcp").textContent = snapshot.dns_tcp_port || "offline";
  const detail = $("dns-detail");
  detail.classList.toggle("is-error", Boolean(snapshot.dns_error));
  detail.classList.toggle("is-warn", !snapshot.dns_error && snapshot.port_conflicts.length > 0);
  if (snapshot.dns_error) {
    detail.textContent = snapshot.dns_error;
  } else {
    detail.textContent = conflictSummary();
  }

  renderConnections();
  renderLogs();
  renderSources();
  renderRules();
  renderFirewall();
  renderSettings();
  $("data-dir").textContent = snapshot.data_dir;
}

function renderConnections() {
  const rows = snapshot.connections.slice(0, 200);
  const body = $("connections-body");
  if (!rows.length) {
    body.innerHTML = snapshot.connection_monitor_supported === false
      ? '<tr><td colspan="7" class="small">Connection monitoring is unavailable on this platform.</td></tr>'
      : '<tr><td colspan="7" class="small">No connections observed.</td></tr>';
    return;
  }
  body.innerHTML = rows.map((c) => `
    <tr>
      <td>${esc(c.process)}</td>
      <td>${esc(c.pid)}</td>
      <td>${esc(c.protocol)}</td>
      <td>${esc(c.local_addr)}:${esc(c.local_port)}</td>
      <td>${esc(c.remote_addr)}:${esc(c.remote_port)}</td>
      <td>${esc(c.state)}</td>
      <td class="small">${fmtBytes(c.bytes_out)} / ${fmtBytes(c.bytes_in)}</td>
    </tr>`).join("");
}

function renderLogs() {
  const list = $("logs");
  if (!snapshot.logs.length) {
    list.innerHTML = '<li class="small">No activity yet.</li>';
    return;
  }
  list.innerHTML = snapshot.logs.map((entry) => `
    <li class="${esc(entry.level)}">
      <b>${esc(entry.level)}</b>
      <span class="small">${esc(entry.timestamp)}</span>
      ${esc(entry.message)}
    </li>`).join("");
}

const CATEGORY_ORDER = [
  "Ads & Trackers",
  "Malware",
  "Deception",
  "Mixed Ads/Trackers/Malware",
  "NSFW",
  "Big Tech",
  "Experiments",
  "Unbreak Popular Websites",
];

const CATEGORY_INFO = {
  "Ads & Trackers": "Tracking, advertising and analytics services.",
  "Malware": "Services used to attack devices through technical means.",
  "Deception": "Phishing and fraud services that trick people.",
  "Mixed Ads/Trackers/Malware": "Independent lists covering several harmful categories at once.",
  "NSFW": "Pornography, violence, gambling and mixed adult content.",
  "Big Tech": "Block everything from selected large technology companies.",
  "Experiments": "Experimental lists for telemetry and revocation endpoints.",
  "Unbreak Popular Websites": "Allow-list entries that lift accidental blocks on popular sites and software.",
};

function renderSources() {
  const container = $("category-list");
  if (!snapshot.sources.length) {
    container.innerHTML = '<p class="small">No filter sources.</p>';
    return;
  }

  const groups = new Map();
  snapshot.sources.forEach((source) => {
    if (!groups.has(source.category)) groups.set(source.category, []);
    groups.get(source.category).push(source);
  });
  const categories = CATEGORY_ORDER.filter((category) => groups.has(category));
  groups.forEach((_sources, category) => {
    if (!categories.includes(category)) categories.push(category);
  });

  container.innerHTML = categories.map((category) => {
    const sources = groups.get(category) || [];
    const active = sources.filter((source) => source.enabled).length;
    const checked = active === sources.length;
    const partial = active > 0 && active < sources.length;
    const total = sources.reduce((sum, source) => sum + source.count, 0);
    const lastText = sources
      .map((source) => source.last_updated)
      .filter(Boolean)
      .sort()
      .pop() || "never";

    const rows = sources.map((source) => `
      <li>
        <div>
          <b>${esc(source.name)}</b>
          <div class="small mono">${esc(source.url)}</div>
        </div>
        <div class="source-meta small">${source.count.toLocaleString()} entries · ${esc(source.last_updated || "never")} · ${source.error ? esc(source.error) : source.count === 0 ? "empty" : "ok"}</div>
        <button class="quiet" data-source-remove="${esc(source.id)}">Remove</button>
      </li>`).join("");

    return `
      <article class="category-card">
        <header class="category-head">
          <label class="check">
            <input type="checkbox" data-category-toggle="${esc(category)}" ${checked ? "checked" : ""} ${partial ? 'data-partial="true"' : ""}>
            <strong>${esc(category)}</strong>
          </label>
          <span class="small">${active}/${sources.length} lists active</span>
        </header>
        <p class="small">${esc(CATEGORY_INFO[category] || "Custom category.")}</p>
        <div class="category-summary small">${total.toLocaleString()} entries · last update ${esc(lastText)}</div>
        <details>
          <summary class="small">Show source lists</summary>
          <ul class="source-list">${rows}</ul>
        </details>
      </article>`;
  }).join("");

  container.querySelectorAll('input[data-partial="true"]').forEach((input) => {
    input.indeterminate = true;
  });
}

function ruleChip(action, domain) {
  return `<span class="chip">${esc(domain)}
    <button data-custom-action="${esc(action)}" data-custom-domain="${esc(domain)}" title="Remove">×</button>
  </span>`;
}

function renderRules() {
  const lists = $("custom-lists");
  const chunks = [];
  snapshot.rules.custom_allow.forEach((domain) => chunks.push(ruleChip("allow", domain)));
  snapshot.rules.custom_block.forEach((domain) => chunks.push(ruleChip("block", domain)));
  lists.innerHTML = chunks.length ? chunks.join("") : '<span class="small">No custom domains.</span>';

  const body = $("app-rules-body");
  if (!snapshot.rules.app_rules.length) {
    body.innerHTML = '<tr><td colspan="4" class="small">No app rules.</td></tr>';
    return;
  }
  body.innerHTML = snapshot.rules.app_rules.map((rule) => `
    <tr>
      <td class="mono">${esc(rule.app_match)}</td>
      <td>${esc(rule.action)}</td>
      <td>${esc(rule.scope)}</td>
      <td><button class="quiet" data-app-remove="${esc(rule.id)}">Remove</button></td>
    </tr>`).join("");
}

function renderFirewall() {
  const supported = snapshot.firewall_supported !== false;
  const note = $("firewall-note");
  note.classList.toggle("is-warn", !supported);
  if (supported) {
    note.textContent = "These commands create Windows Firewall rules and need administrator rights. The app reports the failure when it is not elevated.";
  } else {
    note.textContent = `${snapshot.platform} uses DNS filtering only; Windows Firewall rule commands are unavailable on this platform.`;
  }
  $("firewall-form").querySelectorAll("input, button").forEach((el) => {
    el.disabled = !supported;
  });
  ["preset-outbound", "preset-inbound", "clear-firewall"].forEach((id) => {
    $(id).disabled = !supported;
  });

  const body = $("firewall-body");
  if (!snapshot.firewall_rules.length) {
    body.innerHTML = '<tr><td colspan="4" class="small">No rules created by this app.</td></tr>';
    return;
  }
  body.innerHTML = snapshot.firewall_rules.map((rule) => `
    <tr>
      <td class="mono">${esc(rule.name)}</td>
      <td>${esc(rule.direction)}</td>
      <td class="mono">${esc(rule.program || "all")}</td>
      <td><button class="quiet" data-firewall-remove="${esc(rule.name)}" ${supported ? "" : "disabled"}>Remove</button></td>
    </tr>`).join("");
}

function renderSettings() {
  if (!snapshot) return;
  const dnsSupported = snapshot.system_dns_supported !== false;
  const note = $("system-dns-note");
  note.classList.toggle("is-warn", !dnsSupported);
  if (dnsSupported) {
    note.textContent = "Pointing the OS at this resolver is optional and separate from firewall blocking. Changing system DNS needs administrator rights; Reset restores the servers recorded before the change.";
  } else {
    note.textContent = `${snapshot.platform} has no system DNS integration in this build; DNS filtering stays available.`;
  }
  ["dns-report", "dns-apply", "dns-reset", "dns-auto"].forEach((id) => {
    $(id).disabled = !dnsSupported;
  });
  $("dns-reset").disabled = !dnsSupported || !snapshot.system_dns_state;
  $("dns-interface").disabled = !dnsSupported;
  $("dns-interface").placeholder =
    snapshot.platform === "windows"
      ? "12 (Windows interface index)"
      : snapshot.platform === "linux"
        ? "eth0 (Linux interface name)"
        : "interface";
  if (!dnsSupported) $("dns-output").textContent = "System DNS is unavailable on this platform.";

  const savedDns = snapshot.system_dns_state;
  $("dns-saved").textContent = savedDns
    ? `Recorded prior DNS for interface ${savedDns.interface}: IPv4 ${savedDns.ipv4.join(", ") || "none"}; IPv6 ${savedDns.ipv6.join(", ") || "none"}. Reset restores these.`
    : "No prior DNS configuration recorded yet.";
  if (snapshot.system_dns_error) {
    $("dns-saved").textContent += ` Last error: ${snapshot.system_dns_error}`;
  }

  const autostartSupported = snapshot.autostart_supported !== false;
  $("autostart-note").classList.toggle("is-warn", !autostartSupported);
  if (!autostartSupported) {
    $("autostart-note").textContent = "Login autostart is implemented on Windows only.";
  }
  $("autostart-install").disabled = !autostartSupported || snapshot.autostart_installed;
  $("autostart-remove").disabled = !autostartSupported || !snapshot.autostart_installed;
  $("autostart-status").textContent = snapshot.autostart_installed
    ? "Installed: the app and the DNS guard start elevated at login; stopping the app restores normal DNS."
    : "Not installed.";

  const dohSupported = snapshot.doh_supported !== false;
  $("doh-note").classList.toggle("is-warn", !dohSupported);
  if (!dohSupported) {
    $("doh-note").textContent = "Browser DoH policy control is implemented on Windows only.";
  }
  $("doh-disable").disabled = !dohSupported || !!snapshot.doh_policy_state;
  $("doh-restore").disabled = !dohSupported || !snapshot.doh_policy_state;
  $("doh-status").textContent = snapshot.doh_policy_state
    ? "Browser DoH disabled; prior policy values recorded."
    : "No browser DoH policy recorded.";

  if (settingsDirty) return;
  const form = $("settings-form");
  const settings = snapshot.settings;
  if (!settingsLoaded || activeTab === "settings") {
    form.elements.bind_addr.value = settings.bind_addr;
    form.elements.dns_port.value = settings.dns_port;
    form.elements.fallback_port.value = settings.fallback_port;
    form.elements.primary_doh_url.value = settings.primary_doh_url;
    form.elements.fallback_doh_url.value = settings.fallback_doh_url;
    form.elements.update_interval_hours.value = settings.update_interval_hours;
    form.elements.auto_update.checked = settings.auto_update;
    form.elements.block_inbound.checked = settings.block_inbound;
    form.elements.block_all_internet.checked = settings.block_all_internet;
    form.elements.default_action.value = settings.default_action;
    settingsLoaded = true;
  }
}

function bindEvents() {
  document.querySelectorAll(".tab").forEach((button) => {
    button.addEventListener("click", () => {
      activeTab = button.dataset.tab;
      document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("active", tab === button));
      document.querySelectorAll(".panel").forEach((panel) => panel.classList.add("hidden"));
      $(`tab-${activeTab}`).classList.remove("hidden");
      if (activeTab === "settings") renderSettings();
    });
  });

  $("refresh").addEventListener("click", refresh);
  $("update").addEventListener("click", () => action("update_filters", {}, "Filter update started"));
  $("clear-logs").addEventListener("click", () => action("clear_logs", {}, "Log cleared"));

  $("download-all").addEventListener("click", () =>
    action("download_all_filters", {}, "Downloading all filter lists"));

  $("category-list").addEventListener("change", (event) => {
    const category = event.target.dataset.categoryToggle;
    if (category) {
      action("set_category_enabled", {
        category,
        enabled: event.target.checked,
      }, "Filter category updated");
    }
  });
  $("category-list").addEventListener("click", (event) => {
    const id = event.target.dataset.sourceRemove;
    if (id && confirm("Remove this filter source?")) {
      action("remove_source", { id }, "Filter source removed");
    }
  });

  $("source-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const data = new FormData(event.target);
    action("add_source", {
      name: data.get("name"),
      url: data.get("url"),
      format: data.get("format"),
      category: data.get("category"),
    }, "Filter source added");
    event.target.reset();
  });

  $("custom-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const data = new FormData(event.target);
    action("add_custom_domain", {
      action: data.get("action"),
      domain: data.get("domain"),
    }, "Custom domain added");
    event.target.reset();
  });

  $("custom-lists").addEventListener("click", (event) => {
    const actionValue = event.target.dataset.customAction;
    const domain = event.target.dataset.customDomain;
    if (actionValue && domain) action("remove_custom_domain", { action: actionValue, domain }, "Custom domain removed");
  });

  $("app-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const data = new FormData(event.target);
    action("add_app_rule", {
      appMatch: data.get("app_match"),
      action: data.get("action"),
      scope: data.get("scope"),
    }, "App rule added");
    event.target.reset();
  });

  $("app-rules-body").addEventListener("click", (event) => {
    const id = event.target.dataset.appRemove;
    if (id) action("remove_app_rule", { id }, "App rule removed");
  });

  $("firewall-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const data = new FormData(event.target);
    action("apply_app_firewall", { path: data.get("path") }, "Firewall block applied");
    event.target.reset();
  });

  $("preset-outbound").addEventListener("click", () => {
    action("apply_firewall_preset", { preset: "outbound" }, "Outbound block applied");
  });
  $("preset-inbound").addEventListener("click", () => {
    action("apply_firewall_preset", { preset: "inbound" }, "Inbound block applied");
  });
  $("clear-firewall").addEventListener("click", () => {
    if (confirm("Remove firewall rules created by Portmaster-Local?")) {
      action("clear_firewall_rules", {}, "Firewall rules cleared");
    }
  });
  $("firewall-body").addEventListener("click", (event) => {
    const name = event.target.dataset.firewallRemove;
    if (name) action("remove_firewall_rule", { name }, "Firewall rule removed");
  });

  $("settings-form").addEventListener("input", () => { settingsDirty = true; });
  $("settings-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(event.target);
    const settings = {
      bind_addr: data.get("bind_addr"),
      dns_port: Number(data.get("dns_port")),
      fallback_port: Number(data.get("fallback_port")),
      primary_doh_url: data.get("primary_doh_url"),
      fallback_doh_url: data.get("fallback_doh_url"),
      update_interval_hours: Number(data.get("update_interval_hours")),
      auto_update: data.get("auto_update") === "on",
      block_inbound: data.get("block_inbound") === "on",
      block_all_internet: data.get("block_all_internet") === "on",
      default_action: data.get("default_action"),
    };
    try {
      await invoke("set_settings", { settings });
      settingsDirty = false;
      settingsLoaded = false;
      setStatus("Settings saved · restart the app to change the DNS port");
      await refresh();
    } catch (err) {
      setStatus(`Error: ${err}`, true);
    }
  });

  $("dns-report").addEventListener("click", async () => {
    try {
      const report = await invoke("dns_report");
      $("dns-output").textContent = report || "No report.";
    } catch (err) {
      $("dns-output").textContent = `Error: ${err}`;
    }
  });
  $("dns-apply").addEventListener("click", async () => {
    const interfaceValue = $("dns-interface").value.trim();
    try {
      const prior = await invoke("apply_system_dns", {
        interface: interfaceValue,
        port: snapshot.settings.dns_port,
      });
      $("dns-output").textContent =
        `Recorded prior DNS for interface ${prior.interface}:\n` +
        `IPv4: ${prior.ipv4.join(", ") || "none"}\n` +
        `IPv6: ${prior.ipv6.join(", ") || "none"}`;
      setStatus("System DNS changed · prior servers recorded");
      await refresh();
    } catch (err) {
      setStatus(`Error: ${err}`, true);
    }
  });
  $("dns-reset").addEventListener("click", async () => {
    const interfaceValue =
      snapshot.system_dns_state?.interface || $("dns-interface").value.trim();
    try {
      await invoke("reset_system_dns", { interface: interfaceValue });
      setStatus("System DNS restored to recorded servers");
      await refresh();
    } catch (err) {
      setStatus(`Error: ${err}`, true);
    }
  });
  $("dns-auto").addEventListener("click", async () => {
    try {
      const prior = await invoke("apply_system_dns_auto");
      $("dns-interface").value = prior.interface;
      $("dns-output").textContent =
        `Recorded prior DNS for interface ${prior.interface}:\n` +
        `IPv4: ${prior.ipv4.join(", ") || "none"}\n` +
        `IPv6: ${prior.ipv6.join(", ") || "none"}`;
      setStatus("System DNS applied on the active interface");
      await refresh();
    } catch (err) {
      setStatus(`Error: ${err}`, true);
    }
  });
  $("autostart-install").addEventListener("click", () =>
    action("install_autostart", {}, "Login autostart installed"));
  $("autostart-remove").addEventListener("click", () =>
    action("remove_autostart", {}, "Login autostart removed"));
  $("doh-disable").addEventListener("click", () =>
    action("disable_browser_doh", {}, "Browser DoH disabled"));
  $("doh-restore").addEventListener("click", () =>
    action("restore_browser_doh", {}, "Browser DoH restored"));
}

if (!invoke) {
  setStatus("Tauri bridge unavailable. Run the desktop app, not the raw HTML file.", true);
} else {
  bindEvents();
  refresh();
  setInterval(refresh, 3000);
}
