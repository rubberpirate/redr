# EDR Setup & Demo Instructions

This file explains how to build and demo the EDR system using two Ubuntu 24.04 VMs (VirtualBox) as endpoints and your main OS as the monitoring server.

Prereqs (on each machine):
- Rust toolchain (rustup) for builds: https://rustup.rs
- sudo/root access to install and run the agent (agent needs access to /proc, /proc/net, and to watch files)
- nftables (recommended) or iptables if you plan to block IPs

High-level steps:
1. Build server on your main OS (monitor):

```bash
cd /path/to/redr/edr/server
cargo build --release
# then run
EDR_SERVER_TOKEN=local-dev-token ./target/release/edr-server
```

2. Build agent and deploy to each Ubuntu 24.04 VM (endpoints):

```bash
cd /path/to/redr/edr/agent
cargo build --release
# copy the binary to the VM (scp, shared folder, or VirtualBox shared folder)
sudo mkdir -p /opt/edr
sudo cp target/release/edr-agent /opt/edr/
```

3. Configure environment and run agent on each VM as root (or with capabilities needed):

```bash
# on endpoint VM
export EDR_SERVER_URL="http://<monitor-ip>:8080"
export EDR_AGENT_TOKEN="local-dev-token"
export EDR_WATCH_PATHS="/home,/tmp"
sudo /opt/edr/edr-agent
```

4. Observe the server logs (`edr_server.log`) on the monitor host.

Demo scenario:
- Create a test file on an endpoint: `echo evil > /home/ubuntu/test.txt`
- Agent will detect the creation, compute sha256, and send an event. The server will log it.

Automated responses:
- Currently the agent includes helper functions to quarantine files (move to `/var/lib/edr/quarantine`), kill processes and add an nft rule to drop traffic from a source IP. These require root.

Notes & next steps:
- For production-level visibility/control (full process, memory control), add eBPF-based collectors using `aya` or implement a kernel module. Those require extensive testing and kernel headers.
- Run the server behind TLS in production. Here we keep it simple with HTTP for the demo; you can put an Nginx reverse proxy with TLS in front.

UI and remote commands
- The server now provides a small web UI at `http://<monitor-ip>:8080/` that shows live telemetry and allows you to queue commands for endpoints (kill, quarantine, block_ip).
- Agents poll `/commands?host=<hostname>` periodically and execute permitted actions. When an action completes the agent will send back a `command_result` telemetry event.

Security note: command execution requires the agent to run with privileges (root) to perform quarantine, kill, and firewall operations. For safer deployments, run a small privileged helper with minimal capabilities and the main agent unprivileged.

Security:
- Use mTLS or strong tokens in production.
- Run agents with least privilege required and consider systemd units for persistence.
