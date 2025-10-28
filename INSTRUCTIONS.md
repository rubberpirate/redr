# EDR Setup & Demo Instructions

This file explains how to build and demo the EDR system using two Ubuntu 24.04 VMs (VirtualBox) as endpoints and your main OS as the monitoring server.

Prereqs (on each machine):
- Rust toolchain (rustup) for builds: https://rustup.rs
- sudo/root access to install and run the agent (agent needs access to /proc, /proc/net, quarantine operations, and firewall changes)
- nftables (recommended) or iptables if you plan to block IPs/ports

High-level steps:
1. Build the entire workspace (server + agent) on your main OS:

```bash
cd /home/rubberpirate/redr
cargo build --release --workspace
```

2. Run the server on your main OS (monitor):

```bash
# from repository root
./target/release/edr-server
# By default, the server looks for ui/index.html relative to the repo root.
# Alternatively, set EDR_UI_PATH=/path/to/edr/server/ui/index.html if needed.
```

3. Deploy agent to each Ubuntu 24.04 VM (endpoints):

```bash
# Copy the agent binary to the VMs (e.g., via scp or VirtualBox shared folder)
scp /home/rubberpirate/redr/target/release/edr-agent ubuntu@<vm-ip>:/tmp/
# then on the VM:
sudo mkdir -p /opt/edr
sudo mv /tmp/edr-agent /opt/edr/
sudo chmod +x /opt/edr/edr-agent
```

4. Configure environment and run agent on each VM as root (or with CAP_KILL, CAP_NET_ADMIN, etc.):

```bash
# on endpoint VM
export EDR_SERVER_URL="http://<monitor-ip>:8080"
export EDR_AGENT_TOKEN="local-dev-token"
export EDR_WATCH_PATHS="/home,/tmp"
sudo /opt/edr/edr-agent
```

5. Open web UI on your main OS:

```
http://<monitor-ip>:8080
```

The UI provides live tabs for Processes, Network, Files, and Alerts. You can kill/quarantine processes, block ports, view file details, and approve held processes.

Demo scenario:
- Create a test file on an endpoint: `echo evil > /home/ubuntu/test.txt`
  - Agent will detect the creation, compute SHA-256, and send a `file_event`. The server will log it and the UI will show it in the Files tab.
- Run a suspicious process on the endpoint (e.g., `nc -l 1234` or a shell script like `test.sh`):
  - Agent heuristic detects suspicious process names and SIGSTOPs the process.
  - Agent sends a `suspicious_exec` event to the server.
  - The UI Alerts tab shows the event; you can Approve (resume) or Mark Safe (whitelist).
- Quarantine a file:
  - Click on a file in the Files tab, then "Quarantine" — this queues a command for the agent.
  - Agent polls `/commands?host=...`, executes the quarantine (moves file to `/var/lib/edr/quarantine`), and reports `command_result`.
- Block a network port:
  - In the Network tab, click "Block Port" for a given connection.
  - Agent will execute a best-effort nftables rule to drop incoming TCP traffic on that port.

Automated responses and policy:
- Agent periodically fetches policy from server (GET `/policy`).
- Policy includes:
  - `whitelist_commands`: process names/patterns that should not be stopped even if heuristic matches.
  - `whitelist_paths`: file paths that should not be quarantined or flagged.
  - `blacklist_hashes`: SHA-256 hashes of known-malicious files; when a file is created/modified and matches, it is automatically quarantined.
- The UI allows marking alerts safe (POST `/whitelist`) to add patterns to the whitelist and prevent repeat alerts.
- Agents SIGSTOPs suspicious processes and hold them until approved (resume command from UI) or whitelisted.

Notes & next steps:
- For production-level visibility/control (full memory introspection, guaranteed enforcement), add eBPF-based collectors using `aya` or implement a kernel module. Those require extensive testing and kernel headers.
- Run the server behind TLS in production. Here we keep it simple with HTTP for the demo; you can put an Nginx reverse proxy with TLS in front.
- Consider using systemd units for agent and server persistence.
- Add audit trails for all approve/whitelist actions in the UI and persist policies in an embedded DB (e.g., sled or rusqlite).

UI and remote commands
- The server provides a web UI at `http://<monitor-ip>:8080/` with live telemetry and interactive controls:
  - **Processes tab**: Shows latest process snapshots; click Kill or Quarantine.
  - **Network tab**: Shows active connections; click Block Port to queue a port blocking command.
  - **Files tab**: Shows file create/modify events; click a file to view details (path, SHA-256); click Quarantine to queue quarantine command.
  - **Alerts tab**: Shows suspicious events (suspicious execs, file quarantines, command results); click "Mark Safe" to whitelist or "Approve/Resume" to resume held processes.
- Agents poll `/commands?host=<hostname>` every 5 seconds and execute commands (`kill`, `quarantine`, `block_ip`, `block_port`, `resume`). When an action completes, the agent sends a `command_result` telemetry event.
- Agents also poll `/policy?host=<hostname>` every 10 seconds to fetch updated whitelist/blacklist rules.

Security note: Command execution requires the agent to run with elevated privileges (root or specific capabilities: CAP_KILL for kill, CAP_NET_ADMIN for nft rules, write access to `/var/lib/edr/quarantine`). For safer deployments, run a small privileged helper with minimal capabilities and the main agent unprivileged.

Security:
- Use mTLS or strong tokens in production.
- Run agents with least privilege required and consider systemd units for persistence.
