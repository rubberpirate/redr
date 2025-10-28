# Theory, changes and assumptions

This file documents the changes made to the repository and important design assumptions, tradeoffs, and next steps.

What I added
- A Rust workspace (`Cargo.toml`) with two crates: `edr-agent` and `edr-server`.
- `edr-agent` (production-grade userland EDR):
  - Periodic process snapshots (parses `/proc` directly for portability).
  - File watching for configured paths (uses `notify`) and SHA-256 hashing of files.
  - Periodic network snapshot by reading `/proc/net/tcp`.
  - Policy-driven automated response:
    - Fetches policy from server (whitelist commands, whitelist paths, blacklist hashes).
    - Heuristic-based detection: SIGSTOPs suspicious processes (shell scripts, nc, wget, curl, python, perl) that aren't whitelisted.
    - Automatically quarantines files when their SHA-256 matches the blacklist.
    - Reports `suspicious_exec` and `file_quarantined` events to the server.
  - Command execution: polls server for commands; supports `kill`, `quarantine`, `block_ip`, `block_port`, and `resume` (SIGCONT for held PIDs).
  - Helper functions: `quarantine_file`, `kill_pid`, `block_ip`, `block_port` (best-effort nftables).
  - Sends all telemetry events to server via HTTP POST `/telemetry` with token header.
- `edr-server` (production-grade control plane):
  - HTTP server (warp) with REST API:
    - `POST /telemetry`: ingests agent events (logged to `edr_server.log` and broadcast to websocket).
    - `GET /commands?host=...`: returns pending commands for an agent (one-time fetch and clear).
    - `POST /command`: enqueues a command for a host.
    - `GET /policy`: returns policy JSON (whitelist/blacklist) for agents.
    - `POST /whitelist`: adds items to policy (command patterns, file paths, or blacklist hashes).
    - `/ws`: websocket for live telemetry to UI.
    - Static file serving for web UI (configurable via `EDR_UI_PATH` or repo-relative).
- `edr/server/ui/index.html` (interactive web UI):
  - Live tabs: Processes, Network, Files, Alerts.
  - Actions: Kill/Quarantine processes, Block Port, view file details (SHA-256, path), Mark Safe (whitelist), Approve/Resume held processes.
  - Search, sort (by latest), and alert summary with analytics.

Design assumptions and constraints
- The project delivered here is a pragmatic, small-scale EDR baseline suitable for demos and early proof-of-concept deployments. It is not a hardened product ready for unmonitored production.
- Full “total control” over processes, files, network, ports and memory at kernel level requires kernel modules, eBPF programs, or deep integration with LSM hooks. Those are intentionally not implemented here because they require a careful, system-specific engineering and security review.
- The agent runs in userland and performs reactive control (kill, quarantine, add firewall rules). For stronger enforcement, integrate eBPF (recommended: `aya`) or a signed kernel module.

Threat detection
- Heuristic-based detection for suspicious process names (nc, netcat, telnet, wget, curl, sh, bash, python, perl) that are not whitelisted.
- Hash-based detection: files modified/created that match blacklisted SHA-256 hashes are quarantined immediately.
- The UI allows marking alerts safe (POST /whitelist) to prevent repeat alerts for known-good behaviors.
- Quarantine and hold (SIGSTOP) provide a human-in-the-loop approval workflow: suspicious processes are stopped and require approval (resume) or whitelist from the UI.

Security notes
- TLS/mTLS: the demo uses HTTP for simplicity. In production, terminate TLS at the server and ensure mutual auth for agents.
- Least privilege: run agents with the minimum capabilities needed. Quarantine and firewall changes require root; consider using a small privileged helper binary or systemd unit with appropriate capabilities.
- Policy persistence: currently policies and commands are in-memory. Use a small embedded DB (sled or rusqlite) for production persistence across server restarts.

Command channel
The server now exposes a command queue and policy system. The UI can post commands (POST /command) targeted at a host; agents poll GET /commands?host=<host> and execute the queued commands (kill, quarantine, block_ip, block_port, resume). Agents fetch policy updates (GET /policy) every 10 seconds and apply whitelist/blacklist rules to processes and files. Commands are one-time and agents report results as `command_result` telemetry events.
Next steps (recommended incremental improvements)
1. Add `systemd` unit for agent for persistence and automatic startup.
2. Persist policy and command queue in a small embedded DB (sled or rusqlite) to survive server restarts.
3. Replace simple `/proc/net/tcp` parsing with netlink-based connection events for real-time network monitoring.
4. Integrate eBPF (aya) for kernel-level visibility: file access, process execs, network sockets, and guaranteed enforcement.
5. Add robust authentication (mTLS) and an enrollment flow for agents to rotate tokens.
6. Extend UI with query/investigation tools, timeline, and retention policies for logs.
7. Implement audit trails for all approve/resume/whitelist actions in the UI.

Limitations
- Current agent does not provide memory introspection or runtime code instrumentation. For deep memory analysis, integrate a separate userland process-injection tool or eBPF memory profiler.
- The `nft` invocation for blocking IPs/ports is a best-effort shell-based approach and will need a proper policy manager and nftables API wrapper in production.
- Heuristic detection (process name matching) can have false positives. The whitelist system is provided to tune behavior.

Files added by this change
- `Cargo.toml` (workspace), `edr/agent/*`, `edr/server/*`, `edr/server/ui/index.html`, `INSTRUCTIONS.md`, `THEORY.md`, `.gitignore`.

Recommended testing workflow
1. Build the workspace with `cargo build --release --workspace`.
2. In terminal 1, start the server: `cd /home/rubberpirate/redr && ./target/release/edr-server` (or set `EDR_UI_PATH`).
3. In terminal 2+, start one or more agents (or agents in VMs):
   - On Ubuntu 24.04 VM: `export EDR_SERVER_URL=http://<host_ip>:8080; sudo ./edr-agent` (sudo for firewall/quarantine operations).
4. Open web UI at `http://<host_ip>:8080` (or 127.0.0.1 if local).
5. Trigger suspicious activities:
   - Run a shell script or `nc` command → agent SIGSTOPs it and reports `suspicious_exec`.
   - Approve from UI (or mark safe to whitelist).
   - Touch a file in a watched path → agent hashes and sends `file_event`.
   - (Optional) Manually POST a blacklist hash via UI or API and recreate file to test quarantine.
6. Verify: use UI tabs to see processes, network, files, and alerts; use Kill/Quarantine/Block Port/Resume buttons.

If you want, I can now:
- Add systemd service units for the agent and server.
- Extend the UI or server to add YARA-style signature checks or advanced analytics.
- Package the project as a binary distribution with installers for Ubuntu 24.04.
