# Linux EDR - Project Status & Implementation Map

A production-grade Endpoint Detection and Response (EDR) system built in Rust for Ubuntu 24.04 and other Linux distributions. Provides real-time monitoring, automated responses, policy-driven controls, and an interactive web UI.

## 🎯 Project Overview

This EDR implements real-world security monitoring and response capabilities required to detect and respond to threats on Linux endpoints, with a focus on user-space portability and demo readiness.

---

## ✅ Implemented Features (Current Release)

### Core Monitoring Capabilities

1. ✅ **Process Monitoring** - Real-time process snapshots via direct `/proc` parsing (no sysinfo dependency)
2. ✅ **File System Monitoring** - inotify-based file watching (`notify` crate) with SHA-256 hashing
3. ✅ **Network Monitoring** - Parse `/proc/net/tcp` for TCP connection snapshots
4. ✅ **Policy Engine** - Server-side policy with whitelist/blacklist; agents poll every 10 seconds
5. ✅ **Automated Response** - SIGSTOP suspicious processes, quarantine blacklisted files
6. ✅ **Command & Control** - REST API for command queue (kill, quarantine, block_ip, block_port, resume)
7. ✅ **Web UI** - Single-page app with live websocket; tabs for Processes, Network, Files, Alerts
8. ✅ **Human-in-the-Loop** - Hold/approve suspicious processes; Mark Safe to whitelist

### Response Primitives (Implemented)

- ✅ `kill` - SIGKILL via `kill -9`
- ✅ `quarantine` - Move files to `/var/lib/edr/quarantine` with timestamped filenames
- ✅ `block_ip` - Best-effort nftables rule to drop packets from IP
- ✅ `block_port` - Best-effort nftables rule to drop incoming TCP traffic on port
- ✅ `resume` - SIGCONT to resume held processes

### Telemetry Events (Implemented)

- ✅ `process_snapshot` - List of all PIDs with name and command
- ✅ `file_event` - File create/modify with path and SHA-256
- ✅ `file_quarantined` - File moved to quarantine directory
- ✅ `suspicious_exec` - Heuristic-detected suspicious process (nc, shell scripts, curl, etc.)
- ✅ `net_snapshot` - Raw `/proc/net/tcp` lines
- ✅ `command_result` - Result of command execution (success/failure)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│         Management Interface            │
│              (CLI/API)                  │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│            Web UI (Browser)             │
│   Processes | Network | Files | Alerts  │
│   (Kill, Quarantine, Block, Approve)    │
└──────────────┬──────────────────────────┘
               │ websocket + REST
┌──────────────▼──────────────────────────┐
│          EDR Server (Monitor)           │
│    warp HTTP server on :8080            │
│  - POST /telemetry (ingest events)      │
│  - GET /commands?host=... (fetch cmds)  │
│  - POST /command (enqueue cmd)          │
│  - GET /policy (fetch policy)           │
│  - POST /whitelist (update policy)      │
│  - /ws (websocket broadcast)            │
│  - / (serve UI)                         │
│  Logs: edr_server.log (NDJSON)          │
└──────────────┬──────────────────────────┘
               │ HTTP (polling every 5-10s)
┌──────────────▼──────────────────────────┐
│         EDR Agents (Endpoints)          │
│  Rust async binary (tokio runtime)      │
│  - Process monitor (parses /proc)       │
│  - File watcher (notify + SHA-256)      │
│  - Network snapshot (/proc/net/tcp)     │
│  - Policy poller (fetch whitelist/      │
│    blacklist, consult before stopping   │
│    or quarantining)                     │
│  - Command poller (execute kill,        │
│    quarantine, block, resume)           │
│  - Held PIDs (SIGSTOP suspicious procs) │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│         Linux Kernel / OS               │
│   (proc, notify, kill, nft, rename)     │
└─────────────────────────────────────────┘
```

---

## 🚀 Quick Start

1. **Build**:
   ```bash
   cd /home/rubberpirate/redr
   cargo build --release --workspace
   ```

2. **Run server** (on your main OS):
   ```bash
   ./target/release/edr-server
   # Open http://127.0.0.1:8080 or http://<your-ip>:8080
   ```

3. **Deploy agent** (to VMs or endpoints):
   ```bash
   export EDR_SERVER_URL="http://<server-ip>:8080"
   export EDR_AGENT_TOKEN="local-dev-token"
   export EDR_WATCH_PATHS="/home,/tmp"
   sudo ./target/release/edr-agent
   ```

4. **Use Web UI**: Open browser to server address; view Processes, Network, Files, Alerts; kill/quarantine/block/resume/approve.

---

## 📁 Repository Structure

```
redr/
├── Cargo.toml               # Rust workspace manifest
├── README.md                # Project overview
├── INSTRUCTIONS.md          # Step-by-step demo guide
├── THEORY.md                # Design notes, assumptions, next steps
├── map.md                   # This file (status & implementation map)
├── .gitignore               # Ignore target/, edr_server.log, quarantine/
├── edr/
│   ├── agent/
│   │   ├── Cargo.toml       # Agent dependencies (tokio, reqwest, notify, sha2, ...)
│   │   └── src/
│   │       └── main.rs      # Agent: telemetry, policy, commands, response
│   └── server/
│       ├── Cargo.toml       # Server dependencies (warp, futures-util, tokio, ...)
│       ├── src/
│       │   └── main.rs      # Server: REST API, websocket, in-memory storage
│       └── ui/
│           └── index.html   # Web UI (single-page app)
└── target/                  # Cargo build artifacts (gitignored)
    └── release/
        ├── edr-server
        └── edr-agent
```

---

## 🔧 Configuration

### Agent Environment Variables

- `EDR_SERVER_URL` - Server address (default: `http://127.0.0.1:8080`)
- `EDR_AGENT_TOKEN` - Auth token (default: `local-dev-token`)
- `EDR_WATCH_PATHS` - Comma-separated paths to watch (default: `/home,/tmp`)

### Server Environment Variables

- `EDR_UI_PATH` - Path to `index.html` (default: repo-relative `edr/server/ui/index.html`)
- `EDR_SERVER_TOKEN` - (currently unused; placeholder for future auth)

---

## 📊 Current Limitations & Known Gaps

1. **In-Memory Storage**: Commands and policies are not persisted; server restart clears queue. Use sled or rusqlite for persistence.
2. **No TLS**: HTTP only. Add TLS termination (Nginx reverse proxy) or implement mTLS in production.
3. **Best-Effort Enforcement**: `nft` invocations for block_ip/block_port are shell-based; may fail if nftables not installed or rules conflict.
4. **Heuristic False Positives**: Suspicious process detection uses simple name matching; tune whitelist to avoid blocking legitimate tools.
5. **Memory Introspection**: Not implemented. Requires eBPF or kernel module.
6. **No Audit Trail**: Approve/whitelist actions not logged separately; add audit events in future.

---

## 🛣️ Next Steps (Roadmap)

### High Priority
- [ ] Persist policies and commands in embedded DB (sled or rusqlite)
- [ ] Add audit trail for approve/resume/whitelist actions
- [ ] Systemd units for agent and server

### Medium Priority
- [ ] TLS/mTLS support for agent-server communication
- [ ] Netlink-based real-time network monitoring (replace `/proc/net/tcp` polling)
- [ ] Extend UI with timeline view and advanced search

### Low Priority (Future)
- [ ] eBPF integration (aya) for kernel-level process/file/network visibility
- [ ] YARA-style signature engine for file scanning
- [ ] VirusTotal API integration (optional)
- [ ] Memory profiling and runtime code instrumentation

---

## 📖 Documentation

- **README.md** - Project overview, features, architecture
- **INSTRUCTIONS.md** - Demo setup (2 VMs + host monitor)
- **THEORY.md** - Design assumptions, tradeoffs, and detailed notes
- **map.md** (this file) - Current status, features, and roadmap

---

## 🤝 Contributing

This project is a demo/prototype. For production use:
- Review and harden agent privileges (use capabilities instead of root where possible)
- Implement persistent storage and TLS
- Add comprehensive testing and CI/CD
- Conduct security audit of command execution and quarantine paths

---

## 📝 License

(Add your license here, e.g., MIT, Apache-2.0, or proprietary)

---

**Last Updated**: 2025 (after implementing automated response, policy system, and web UI with approval workflows)
               │
┌──────────────▼──────────────────────────┐
│         Monitoring Agents               │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐  │
│  │Process│ │File  │ │Network│ │Memory│  │
│  │Monitor│ │Monitor│ │Monitor│ │Monitor│ │
│  └──────┘ └──────┘ └──────┘ └──────┘  │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│         Linux Kernel APIs               │
│   (proc, netlink, inotify, eBPF)       │
└─────────────────────────────────────────┘
```

---
