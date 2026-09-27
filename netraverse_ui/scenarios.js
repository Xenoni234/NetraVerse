/* NetraVerse scenario engine — deterministic multi-campaign timelines.
 * Windows are 60 s. Risk P(attack within 300 s) is decoded per window.
 * Campaigns forecast (cross threshold) ahead of onset; a decision reshapes the
 * post-decision risk. Hosts/labels follow the netraverse_campaign dataset.        */

const THRESHOLD = 0.43;
const WIN = 60; // seconds per state window

const STAGES = ["Benign", "Reconnaissance", "Initial Access", "Lateral Movement",
  "Command & Control", "Exfiltration", "Impact"];

// Risk = P(attack within 300 s). It must cross the alert threshold at alertAt
// (that is the forecast firing `lead` seconds before onset), then rise to peak
// as the predicted attack actually lands at onset.
function ramp(i, alertAt, onset, peak) {
  if (i < alertAt - 1) return 0.03 + 0.012 * Math.sin(i * 1.7);
  if (i < alertAt) return 0.18;                       // rising, still below 0.43
  if (i < onset) {                                    // forecast fired: above threshold, climbing to peak
    const span = Math.max(1, onset - alertAt);
    const t = (i - alertAt) / span;
    return 0.55 + (peak - 0.55) * t;
  }
  return peak;
}

/* A campaign definition. onset = window where the attack lands.
 * alertAt = window where forecast first crosses threshold (lead = onset-alertAt windows). */
function makeCampaign(c) {
  return Object.assign({
    id: c.id, name: c.name, mitre: c.mitre, tactic: c.tactic,
    src: c.src, dst: c.dst, srcLabel: c.srcLabel || c.src, dstLabel: c.dstLabel || c.dst,
    peak: c.peak, alertAt: c.alertAt, onset: c.onset, stage: c.stage,
    leadSec: (c.onset - c.alertAt) * WIN,
    reco: c.reco, action: c.action, cmd: c.cmd,
    shap: c.shap, reasoning: c.reasoning,
    decayFrom: null, decided: null, // filled at runtime
  }, {});
}

// per-window risk for a campaign given the operator's decision
function campaignRisk(c, i, state) {
  const base = ramp(i, c.alertAt, c.onset, c.peak);
  if (state.decision == null || i < state.decidedAt) return base;
  const k = i - state.decidedAt;
  if (state.decision === "reject") {
    // no action: rises to realised impact then plateaus high
    return Math.min(0.98, c.peak + 0.10 + 0.02 * k);
  }
  // accept / modify: steady exponential decay from the risk at decision time
  const r0 = state.riskAtDecision;
  const rate = state.decision === "modify" ? 0.62 : 0.5;
  return Math.max(0.03, r0 * Math.pow(rate, k));
}

/* Build the full scenario object the UI consumes. */
function buildScenario(kind) {
  const spec = SCENARIO_SPECS[kind];
  const campaigns = spec.campaigns.map(makeCampaign);
  const nWindows = spec.windows;
  return {
    kind, title: spec.title, subtitle: spec.subtitle, iface: spec.iface,
    fileHint: spec.fileHint, pipeline: spec.pipeline,
    nWindows, threshold: THRESHOLD, win: WIN, stages: STAGES,
    hosts: spec.hosts, campaigns,
  };
}

/* ---- host topology (subnets) ---- */
const HOSTS = {
  gateway: { ip: "10.20.0.1", role: "gateway", label: "core-gw" },
  servers: [
    { ip: "10.20.0.11", label: "auth-svc" }, { ip: "10.20.0.12", label: "ssh-jump" },
    { ip: "10.20.0.13", label: "db-primary" }, { ip: "10.20.0.14", label: "app-01" },
    { ip: "10.20.0.15", label: "app-02" }, { ip: "10.20.0.16", label: "file-store" },
    { ip: "10.20.0.17", label: "backup" },
  ],
  ext: [
    { ip: "10.13.37.5", label: "ext-host-5" }, { ip: "10.13.37.7", label: "ext-host-7" },
    { ip: "10.13.37.8", label: "ext-host-8" }, { ip: "10.13.37.10", label: "ext-host-10" },
    { ip: "10.13.37.11", label: "ext-host-11" },
  ],
};

const CIC = "CIC-IDS2017";

const SCENARIO_SPECS = {
  csv: {
    title: "Flow capture replay",
    subtitle: "NetFlow/IPFIX flow records · unified feature schema",
    iface: "upload",
    fileHint: "netraverse_campaign.csv",
    pipeline: ["read flow records", "normalize schema", "fuse flow+packet features",
      "build 60 s windows", "encode latent state", "prior-only rollout · 300 s"],
    windows: 24,
    hosts: HOSTS,
    campaigns: [
      {
        id: "c1", name: "Network service scan", tactic: "Reconnaissance", stage: 1,
        mitre: "T1046", src: "10.13.37.5", srcLabel: "ext-host-5",
        dst: "10.20.0.0/24", dstLabel: "server subnet",
        alertAt: 2, onset: 5, peak: 0.91,
        reco: "Block source 10.13.37.5 at the core gateway ACL",
        action: "Block source at gateway",
        cmd: "iptables -A FORWARD -s 10.13.37.5 -j DROP",
        shap: [["distinct destinations contacted (fan-out)", 0.34, 1],
        ["SYN-only flows / s", 0.27, 1], ["distinct dst ports", 0.19, 1],
        ["mean flow duration", -0.12, -1], ["bytes per flow", -0.08, -1]],
        reasoning: "The source 10.13.37.5 is touching 41 distinct destinations in the 10.20.0.0/24 server subnet with SYN-only, short-lived flows and a rising distinct-port count — a textbook horizontal + vertical scan (MITRE T1046). The latent trajectory places the network at Reconnaissance and the 300 s rollout puts P(progression → Initial Access) at 0.91 within ~180 s. Recommend blocking the source at the gateway before it fingerprints an exploitable service.",
      },
      {
        id: "c2", name: "SSH / FTP brute force", tactic: "Credential Access", stage: 2,
        mitre: "T1110", src: "10.13.37.7", srcLabel: "ext-host-7",
        dst: "10.20.0.12", dstLabel: "ssh-jump",
        alertAt: 8, onset: 10, peak: 0.87,
        reco: "Isolate ssh-jump 10.20.0.12 and enforce credential lockout",
        action: "Rate-limit + credential lockout on 10.20.0.12",
        cmd: "fail2ban-client set sshd banip 10.13.37.7; ufw limit 22/tcp",
        shap: [["failed-auth attempts / s", 0.38, 1], ["repeated dst port 22/21", 0.24, 1],
        ["small uniform payload size", 0.17, 1], ["connection reset ratio", 0.11, 1],
        ["source entropy", -0.06, -1]],
        reasoning: "10.13.37.7 is hammering ssh-jump (10.20.0.12) on ports 22 and 21 with a high failed-auth rate and small, uniform payloads — a credential brute force (T1110). Given the earlier recon, the world model rolls this forward to a 0.87 probability of a successful login → Initial Access inside ~120 s. Recommend rate-limiting the source and forcing a credential lockout on the jump host.",
      },
      {
        id: "c3", name: "Exfiltration over C2 channel", tactic: "Exfiltration", stage: 5,
        mitre: "T1041", src: "10.20.0.14", srcLabel: "app-01",
        dst: "10.13.37.10", dstLabel: "ext-host-10",
        alertAt: 15, onset: 18, peak: 0.94,
        reco: "Quarantine app-01 10.20.0.14 and null-route the C2 endpoint",
        action: "Quarantine 10.20.0.14 + block C2 egress",
        cmd: "nft add rule inet filter output ip daddr 10.13.37.10 drop",
        shap: [["outbound bytes / inbound bytes", 0.41, 1], ["beacon interval regularity", 0.29, 1],
        ["long-lived TLS to new host", 0.16, 1], ["off-hours activity", 0.09, 1],
        ["known-good ASN", -0.05, -1]],
        reasoning: "An internal host app-01 (10.20.0.14) has flipped to a highly asymmetric outbound/inbound byte ratio with regular beacon intervals to a never-before-seen external host 10.13.37.10 — data exfiltration over an established C2 channel (T1041). This is the terminal kill-chain stage; the rollout puts P(bulk exfiltration) at 0.94 within ~180 s. Recommend quarantining app-01 and null-routing the C2 endpoint immediately.",
      },
    ],
  },

  pcap: {
    title: "Packet capture replay",
    subtitle: "PCAP-derived flow + packet features · unified schema",
    iface: "upload",
    fileHint: "netraverse_campaign.pcap",
    pipeline: ["parse packets (Scapy)", "reassemble flows", "extract packet features",
      "fuse flow+packet features", "build 60 s windows", "encode + rollout · 300 s"],
    windows: 24,
    hosts: HOSTS,
    campaigns: [
      {
        id: "p1", name: "Lateral movement — remote services", tactic: "Lateral Movement", stage: 3,
        mitre: "T1021", src: "10.20.0.12", srcLabel: "ssh-jump",
        dst: "10.20.0.15", dstLabel: "app-02",
        alertAt: 2, onset: 5, peak: 0.89,
        reco: "Isolate ssh-jump 10.20.0.12 from the internal server VLAN",
        action: "Isolate 10.20.0.12 (internal VLAN)",
        cmd: "nft add rule inet filter forward ip saddr 10.20.0.12 ip daddr 10.20.0.0/24 drop",
        shap: [["new internal peer count", 0.36, 1], ["SMB/RDP/SSH east-west flows", 0.28, 1],
        ["admin-share access pattern", 0.18, 1], ["packet inter-arrival regularity", 0.10, 1],
        ["prior baseline peers", -0.09, -1]],
        reasoning: "The packet capture shows ssh-jump (10.20.0.12) — already the brute-force target — now opening east-west SSH/SMB sessions to internal peers it has never contacted, including app-02 (10.20.0.15). This is hands-on-keyboard lateral movement (T1021). The latent state has advanced to Lateral Movement and the rollout gives 0.89 probability of a second host compromise within ~180 s. Recommend isolating the jump host from the internal server VLAN.",
      },
      {
        id: "p2", name: "HTTPS C2 beaconing", tactic: "Command & Control", stage: 4,
        mitre: "T1071", src: "10.20.0.15", srcLabel: "app-02",
        dst: "10.13.37.8", dstLabel: "ext-host-8",
        alertAt: 9, onset: 11, peak: 0.9,
        reco: "Block C2 egress from app-02 10.20.0.15 and capture the JA3",
        action: "Block C2 egress from 10.20.0.15",
        cmd: "nft add rule inet filter output ip saddr 10.20.0.15 ip daddr 10.13.37.8 drop",
        shap: [["beacon interval regularity", 0.37, 1], ["self-signed / rare JA3", 0.26, 1],
        ["fixed small request size", 0.19, 1], ["jitter within 5%", 0.12, 1],
        ["session to CDN ASN", -0.07, -1]],
        reasoning: "Post-compromise, app-02 (10.20.0.15) is beaconing to 10.13.37.8 at a near-fixed interval with <5% jitter and a rare, self-signed TLS fingerprint (JA3) — an application-layer C2 channel (T1071). The world model reads a stable Command & Control latent state and forecasts 0.90 probability of tasking/exfil within ~120 s. Recommend blocking egress to the C2 host and preserving the JA3 for hunting.",
      },
      {
        id: "p3", name: "Service flood (DoS)", tactic: "Impact", stage: 6,
        mitre: "T1498", src: "10.13.37.11", srcLabel: "ext-host-11",
        dst: "10.20.0.11", dstLabel: "auth-svc",
        alertAt: 15, onset: 18, peak: 0.93,
        reco: "Enable SYN-cookie rate limiting and upstream scrub for auth-svc",
        action: "Rate-limit + upstream scrub for 10.20.0.11",
        cmd: "iptables -A INPUT -p tcp --syn -d 10.20.0.11 -m limit --limit 40/s -j ACCEPT",
        shap: [["inbound SYN rate", 0.43, 1], ["source IP dispersion", 0.24, 1],
        ["half-open connection count", 0.18, 1], ["mean payload size", -0.11, -1],
        ["completed handshakes", -0.14, -1]],
        reasoning: "auth-svc (10.20.0.11) is absorbing a steep inbound SYN rate with a growing half-open connection backlog and rising source dispersion — a network denial-of-service aimed at the auth tier (T1498). The rollout puts P(service availability loss) at 0.93 within ~180 s. Recommend SYN-cookie rate limiting at the edge and engaging upstream scrubbing.",
      },
    ],
  },

  live: {
    title: "Live monitor",
    subtitle: "sensor eth0 · streaming 60 s windows",
    iface: "eth0",
    fileHint: null,
    pipeline: ["sniff packets", "flow assembly", "feature fusion", "encode + rollout · 300 s"],
    windows: 20,
    hosts: HOSTS,
    // live campaigns are injected by triggers; templates keyed by scenario name
    campaigns: [],
  },
};

/* live trigger -> campaign template (alertAt/onset are relative to trigger time) */
const LIVE_TEMPLATES = {
  recon_scan: {
    id: "l_recon", name: "Network service scan", tactic: "Reconnaissance", stage: 1, mitre: "T1046",
    src: "10.13.37.5", srcLabel: "ext-host-5", dst: "10.20.0.0/24", dstLabel: "server subnet",
    lead: 3, dur: 3, peak: 0.9,
    reco: "Block source 10.13.37.5 at the core gateway ACL", action: "Block source at gateway",
    cmd: "iptables -A FORWARD -s 10.13.37.5 -j DROP",
    shap: [["distinct destinations contacted (fan-out)", 0.34, 1], ["SYN-only flows / s", 0.27, 1],
    ["distinct dst ports", 0.19, 1], ["mean flow duration", -0.12, -1]],
    reasoning: "Live sensor sees 10.13.37.5 fanning out across the 10.20.0.0/24 subnet with SYN-only short flows — active reconnaissance (T1046). Rollout: 0.90 progression risk within ~180 s. Block the source at the gateway.",
  },
  brute_force: {
    id: "l_bf", name: "SSH brute force", tactic: "Credential Access", stage: 2, mitre: "T1110",
    src: "10.13.37.7", srcLabel: "ext-host-7", dst: "10.20.0.12", dstLabel: "ssh-jump",
    lead: 2, dur: 3, peak: 0.87,
    reco: "Rate-limit source and enforce credential lockout on 10.20.0.12",
    action: "Rate-limit + lockout on 10.20.0.12",
    cmd: "fail2ban-client set sshd banip 10.13.37.7; ufw limit 22/tcp",
    shap: [["failed-auth attempts / s", 0.38, 1], ["repeated dst port 22", 0.24, 1],
    ["small uniform payload", 0.17, 1], ["connection reset ratio", 0.11, 1]],
    reasoning: "10.13.37.7 is driving a high failed-auth rate against ssh-jump (10.20.0.12) on port 22 — credential brute force (T1110). Rollout: 0.87 login-success risk within ~120 s. Rate-limit and lock out.",
  },
  lateral_movement: {
    id: "l_lat", name: "Lateral movement", tactic: "Lateral Movement", stage: 3, mitre: "T1021",
    src: "10.20.0.12", srcLabel: "ssh-jump", dst: "10.20.0.15", dstLabel: "app-02",
    lead: 2, dur: 3, peak: 0.89,
    reco: "Isolate ssh-jump 10.20.0.12 from the internal server VLAN", action: "Isolate 10.20.0.12",
    cmd: "nft add rule inet filter forward ip saddr 10.20.0.12 ip daddr 10.20.0.0/24 drop",
    shap: [["new internal peer count", 0.36, 1], ["east-west SSH/SMB flows", 0.28, 1],
    ["admin-share access", 0.18, 1], ["inter-arrival regularity", 0.10, 1]],
    reasoning: "ssh-jump (10.20.0.12) is opening east-west sessions to new internal peers incl. app-02 — lateral movement (T1021). Rollout: 0.89 second-host-compromise risk within ~180 s. Isolate the jump host.",
  },
  c2_beacon: {
    id: "l_c2", name: "HTTPS C2 beaconing", tactic: "Command & Control", stage: 4, mitre: "T1071",
    src: "10.20.0.14", srcLabel: "app-01", dst: "10.13.37.8", dstLabel: "ext-host-8",
    lead: 3, dur: 3, peak: 0.9,
    reco: "Block C2 egress from app-01 10.20.0.14 and capture the JA3", action: "Block C2 egress from 10.20.0.14",
    cmd: "nft add rule inet filter output ip saddr 10.20.0.14 ip daddr 10.13.37.8 drop",
    shap: [["beacon interval regularity", 0.37, 1], ["rare JA3 fingerprint", 0.26, 1],
    ["fixed small request size", 0.19, 1], ["jitter within 5%", 0.12, 1]],
    reasoning: "app-01 (10.20.0.14) is beaconing to 10.13.37.8 at a fixed interval with a rare JA3 — application-layer C2 (T1071). Rollout: 0.90 tasking/exfil risk within ~180 s. Block egress and keep the JA3.",
  },
  data_exfil: {
    id: "l_exf", name: "Exfiltration over C2", tactic: "Exfiltration", stage: 5, mitre: "T1041",
    src: "10.20.0.16", srcLabel: "file-store", dst: "10.13.37.10", dstLabel: "ext-host-10",
    lead: 3, dur: 3, peak: 0.94,
    reco: "Quarantine file-store 10.20.0.16 and null-route the C2 endpoint", action: "Quarantine 10.20.0.16 + block egress",
    cmd: "nft add rule inet filter output ip daddr 10.13.37.10 drop",
    shap: [["outbound/inbound byte ratio", 0.41, 1], ["beacon interval regularity", 0.29, 1],
    ["long-lived TLS to new host", 0.16, 1], ["off-hours activity", 0.09, 1]],
    reasoning: "file-store (10.20.0.16) shows a strongly asymmetric outbound byte ratio to a new external host — exfiltration over C2 (T1041). Rollout: 0.94 bulk-exfil risk within ~180 s. Quarantine and null-route now.",
  },
  dos_flood: {
    id: "l_dos", name: "Service flood (DoS)", tactic: "Impact", stage: 6, mitre: "T1498",
    src: "10.13.37.11", srcLabel: "ext-host-11", dst: "10.20.0.11", dstLabel: "auth-svc",
    lead: 3, dur: 3, peak: 0.93,
    reco: "SYN-cookie rate limiting and upstream scrub for auth-svc 10.20.0.11", action: "Rate-limit + scrub 10.20.0.11",
    cmd: "iptables -A INPUT -p tcp --syn -d 10.20.0.11 -m limit --limit 40/s -j ACCEPT",
    shap: [["inbound SYN rate", 0.43, 1], ["source IP dispersion", 0.24, 1],
    ["half-open connections", 0.18, 1], ["completed handshakes", -0.14, -1]],
    reasoning: "auth-svc (10.20.0.11) is taking a steep SYN flood with a rising half-open backlog — network DoS (T1498). Rollout: 0.93 availability-loss risk within ~180 s. Rate-limit at the edge and scrub upstream.",
  },
};

window.NV = { THRESHOLD, WIN, STAGES, HOSTS, buildScenario, campaignRisk, ramp, LIVE_TEMPLATES, SCENARIO_SPECS };
