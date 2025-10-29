# Update Agent on VMs with Domain Detection

## The Problem
Your VMs are running the OLD agent without domain detection. The server logs show:
- ✅ Receiving `net_snapshot` events
- ❌ NOT receiving `domains_detected` events

## Solution: Deploy Updated Agent

### Step 1: Copy Agent Binary to VMs

From your host machine, copy the new agent to each VM:

```bash
# For VM 1 (redr)
scp /home/rubberpirate/redr/edr/target/release/edr-agent user@VM1_IP:/home/user/redr/target/release/

# For VM 2 (edr/rust-edr-dev)
scp /home/rubberpirate/redr/edr/target/release/edr-agent user@VM2_IP:/home/user/redr/target/release/
```

Or use the VM shared folder if you have one configured.

### Step 2: On Each VM - Stop Old Agent

```bash
# SSH into the VM or use the VM terminal
ssh user@VM_IP

# Stop the old agent
sudo pkill -9 edr-agent
```

### Step 3: On Each VM - Start New Agent

```bash
cd /home/user/redr  # or wherever you placed the binary

export EDR_SERVER_URL="http://172.16.0.2:8080"
export EDR_AGENT_TOKEN="local-dev-token"
export EDR_WATCH_PATHS="/home,/tmp"
sudo -E target/release/edr-agent
```

### Step 4: Verify Domain Detection

1. **On the VM**, browse to some websites:
   ```bash
   curl -I google.com
   curl -I youtube.com
   curl -I github.com
   ```

2. **On your host**, check server logs:
   ```bash
   # You should see:
   recv domains_detected from redr
   recv domains_detected from edr
   ```

3. **In the Web UI** (`http://172.16.0.2:8080`):
   - Click the **Sites** tab
   - You should see domains like `google.com`, `youtube.com`, etc.

## Quick Test Without VM Update

If you want to test the feature locally first:

```bash
# On your HOST machine (not in VM)
cd /home/rubberpirate/redr

# Set hostname to something different
export HOSTNAME="test-host"

# Run the new agent locally
export EDR_SERVER_URL="http://localhost:8080"
export EDR_AGENT_TOKEN="local-dev-token"
export EDR_WATCH_PATHS="/tmp"
sudo -E edr/target/release/edr-agent
```

Then browse some sites on your host and check the Sites tab.

## Alternative: Shared Folder Method

If your VMs have a shared folder with the host:

1. **On Host**: The binary is already at `/home/rubberpirate/redr/edr/target/release/edr-agent`
2. **On VM**: Access the shared folder and copy the binary:
   ```bash
   cp /path/to/shared/folder/edr/target/release/edr-agent ~/redr/target/release/
   ```

## Troubleshooting

### Domain Detection Not Working?

Check these common issues:

1. **Agent is old version**
   - Check build timestamp: `ls -la target/release/edr-agent`
   - Should be recent (today's date)

2. **No external connections**
   - Domain detection only works for **external IPs**
   - Local IPs (127.x, 192.168.x, 10.x) are filtered out
   - Try: `curl -I google.com` or visit a real website

3. **DNS lookup failing**
   - Check DNS is working: `nslookup 8.8.8.8`
   - Check `/etc/resolv.conf` has valid nameservers

4. **Permissions**
   - Agent must run with `sudo -E` for /proc access
   - Check with: `ps aux | grep edr-agent` (should show root/sudo)

### Server Not Receiving Events?

1. **Check server is running**:
   ```bash
   curl http://172.16.0.2:8080
   ```

2. **Check agent can reach server**:
   ```bash
   # On VM
   curl http://172.16.0.2:8080/policy?host=test
   ```

3. **Check firewall**:
   ```bash
   sudo ufw status
   # Port 8080 should be allowed
   ```

## Expected Server Output

When domain detection is working, you'll see:

```
recv net_snapshot from redr
recv domains_detected from redr      <-- NEW!
recv net_snapshot from edr
recv domains_detected from edr        <-- NEW!
```

## Expected UI

The **Sites** tab should show:

```
╔═══════════════════════════════════════════════════════════════╗
║ Host    │ Domain/Website │ IP Address     │ Port │ Status  ║
╠═══════════════════════════════════════════════════════════════╣
║ redr    │ google.com     │ 142.250.185.46 │ 443  │ ✓Active ║
║ redr    │ youtube.com    │ 142.250.185.78 │ 443  │ ✓Active ║
║ edr     │ github.com     │ 140.82.121.4   │ 443  │ ✓Active ║
╚═══════════════════════════════════════════════════════════════╝
```

Click **"Block Site"** to block access to any domain!
