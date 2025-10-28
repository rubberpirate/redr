# Theory, changes and assumptions

This file documents the changes made to the repository and important design assumptions, tradeoffs, and next steps.

What I added
- A Rust workspace (`Cargo.toml`) with two crates: `edr-agent` and `edr-server`.
- `edr-agent` (basic):
  - Periodic process snapshots (uses `sysinfo`).
  - File watching for configured paths (uses `notify`) and SHA-256 hashing of files.
  - Periodic network snapshot by reading `/proc/net/tcp`.
  - Simple helper response functions: quarantine file (move to `/var/lib/edr/quarantine`), kill PID, and a best-effort `nft` IP block call.
  - Sends events to server via HTTP POST to `/telemetry` with a shared token header.
- `edr-server` (basic):
  - HTTP server (warp) with `POST /telemetry` that writes JSON lines to `edr_server.log` and prints events.

Design assumptions and constraints
- The project delivered here is a pragmatic, small-scale EDR baseline suitable for demos and early proof-of-concept deployments. It is not a hardened product ready for unmonitored production.
- Full “total control” over processes, files, network, ports and memory at kernel level requires kernel modules, eBPF programs, or deep integration with LSM hooks. Those are intentionally not implemented here because they require a careful, system-specific engineering and security review.
- The agent runs in userland and performs reactive control (kill, quarantine, add firewall rules). For stronger enforcement, integrate eBPF (recommended: `aya`) or a signed kernel module.

Threat detection
- Basic detection is hash-based for files. The server can be extended to query VirusTotal or YARA-style signatures.
- To call VirusTotal: use `reqwest` on the server and supply `VIRUSTOTAL_API_KEY`. This repo includes placeholders and documentation for that extension; do not store keys in source control.
 Basic detection is hash-based for files. The server can be extended to query YARA-style signatures or external threat intel, but VirusTotal is not required for the core demo and has been removed from the main flow to avoid external dependencies.

Security notes
- TLS/mTLS: the demo uses HTTP for simplicity. In production, terminate TLS at the server and ensure mutual auth for agents.
- Least privilege: run agents with the minimum capabilities needed. Quarantine and firewall changes require root; consider using a small privileged helper binary or systemd unit with appropriate capabilities.

 Command channel
 The server now exposes a simple command queue. The UI can post commands (POST /command) targeted at a host; agents poll GET /commands?host=<host> and execute the queued commands. Commands are one-time and agents report results as `command_result` telemetry events.
Next steps (recommended incremental improvements)
1. Add `systemd` unit for agent for persistence and automatic startup.
2. Replace simple `/proc/net/tcp` parsing with netlink-based connection events for real-time network monitoring.
3. Integrate eBPF (aya) for kernel-level visibility: file access, process execs, network sockets.
4. Add robust authentication (mTLS) and an enrollment flow for agents to rotate tokens.
5. Add a small UI or CLI for query and investigation and retention policies for logs.

Limitations
- Current agent does not provide memory introspection or runtime code instrumentation.
- The `nft` invocation is a best-effort shell-based approach and will need a proper policy manager in production.

Files added by this change
- `Cargo.toml` (workspace), `edr/agent/*`, `edr/server/*`, `INSTRUCTIONS.md`, `THEORY.md`.

If you want, I can now:
- Try to build the workspace here and show build output.
- Add systemd service units and example nft scripts.
- Implement a VirusTotal lookup on the server and an automated response flow (e.g., kill processes using a flagged binary).
