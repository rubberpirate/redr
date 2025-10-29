# New EDR Features - Website Monitoring & Blocking

## 🌐 What's New

### 1. **Sites Tab - Website Monitoring**
The EDR now detects and displays all websites/domains that endpoints are accessing through browsers or other programs.

**Features:**
- Real-time domain detection using reverse DNS lookups
- Shows domain name, IP address, and port
- Search functionality to filter sites
- Status indicator (Active/Blocked)

### 2. **Domain Blocking**
Block access to specific websites on any endpoint.

**How it works:**
- Click "Block Site" button next to any domain
- The agent adds the domain to `/etc/hosts` pointing to `0.0.0.0`
- This prevents the endpoint from accessing that website
- Works for all programs (browsers, curl, wget, etc.)

**Commands:**
- `Block Site` - Prevents endpoint from accessing the website
- `Unblock` - Restores access to a blocked website

### 3. **Port Blocking with Visual Indicators**
Enhanced port blocking with better UI feedback.

**Features:**
- Blocked ports show in **RED** with a "Block Port" button
- Unblocked/active ports show with an "Unblock" button (GREEN)
- Visual status makes it easy to see what's blocked at a glance

**Commands:**
- `Block Port` - Blocks a specific port using nftables firewall rules
- `Unblock` - Removes the firewall rule to restore port access

## 🔧 Technical Implementation

### Agent Side (`edr/agent/src/main.rs`)
**New Functions:**
- `unblock_port()` - Removes nftables drop rule for a port
- `block_domain()` - Adds domain to /etc/hosts
- `unblock_domain()` - Removes domain from /etc/hosts

**Network Monitoring Enhanced:**
- Parses `/proc/net/tcp` to get remote IP addresses
- Performs reverse DNS lookups on external IPs
- Sends `domains_detected` events with domain, IP, and port info
- Runs every 5 seconds

**New Command Handlers:**
- `unblock_port` - Executes port unblocking
- `block_domain` - Executes domain blocking
- `unblock_domain` - Executes domain unblocking

### Server Side (`edr/server/ui/index.html`)
**New UI Components:**
- Sites tab with domain table
- Search box for filtering domains
- Block/Unblock buttons with status indicators
- Visual styling for blocked vs active states

**New State:**
```javascript
domains: new Map(),         // host -> [{domain, ip, port, timestamp, blocked}]
blockedPorts: new Set(),    // Tracks which ports are blocked
blockedDomains: new Set(),  // Tracks which domains are blocked
```

**New Functions:**
- `renderSites()` - Displays all detected websites
- `blockDomain()` - Sends block_domain command
- `unblockDomain()` - Sends unblock_domain command
- `unblockPort()` - Sends unblock_port command
- Updated `blockPort()` to track blocked state

**Event Handler:**
- Handles `domains_detected` events from agents
- Updates domains map and renders Sites tab

## 📋 Usage Guide

### Monitoring Websites
1. Open the EDR Dashboard at `http://172.16.0.2:8080`
2. Click the **Sites** tab
3. You'll see all domains/websites being accessed by your endpoints
4. Use the search box to find specific sites

### Blocking a Website
1. Find the domain in the Sites tab
2. Click the **Block Site** button
3. Confirm the action
4. The status changes to "🚫 Blocked" and the button changes to "Unblock"
5. The endpoint can no longer access that website

### Unblocking a Website
1. Find the blocked domain (shows as "🚫 Blocked")
2. Click the **Unblock** button
3. Confirm the action
4. Access is restored

### Managing Ports
1. Go to the **Network** tab
2. Find the port you want to block/unblock
3. Click **Block Port** (shows in red when blocked)
4. Click **Unblock** to restore access (shows in green when active)

## 🔍 How Domain Detection Works

1. **Agent monitors `/proc/net/tcp`** every 5 seconds
2. **Extracts remote IP addresses** from established connections
3. **Filters out local/private IPs** (127.x.x.x, 192.168.x.x, 10.x.x.x)
4. **Performs reverse DNS lookup** on each public IP
5. **Sends domain info to server** via `domains_detected` event
6. **UI displays** the domain name, IP, and port

## ⚠️ Requirements & Notes

### Agent Requirements
- `nftables` or `iptables` installed for port blocking
- Root/sudo privileges (already required for agent)
- `/etc/hosts` write access (already available with sudo)

### Limitations
- Domain blocking via `/etc/hosts` doesn't work if programs use IP directly
- Reverse DNS lookups add slight overhead (async, non-blocking)
- Some IPs may not have reverse DNS entries (shows IP only)
- Port blocking rules persist until system reboot or manual removal

### DNS Caching
- Browsers may cache DNS lookups, so blocked sites might work for a few seconds
- Clearing browser cache or restarting the browser forces the new `/etc/hosts` entry

## 🎨 UI Enhancements

**Color Coding:**
- 🔴 **Red buttons** = Blocking actions (Block Site, Block Port)
- 🟢 **Green buttons** = Unblocking actions (Unblock)
- ✓ **Green status** = Active/Allowed
- 🚫 **Red status** = Blocked

**Status Badges:**
- Service names (HTTP, HTTPS, SSH, etc.)
- Data consumption (KB/MB/GB)
- Active vs Blocked indicators

## 🚀 Deployment

### Update Agent on VMs
```bash
cd /home/rubberpirate/redr
cargo build --release --bin edr-agent

# Deploy to VMs (use scp or rsync)
scp target/release/edr-agent user@vm:/home/user/redr/

# On VM, run:
export EDR_SERVER_URL="http://172.16.0.2:8080"
export EDR_AGENT_TOKEN="local-dev-token"
export EDR_WATCH_PATHS="/home,/tmp"
sudo -E target/release/edr-agent
```

### Server Already Updated
The server is already running with the new UI. Just refresh your browser.

## 📊 Testing

1. **Test Domain Detection:**
   - On an agent VM, browse to a website (e.g., `curl example.com`)
   - Check the Sites tab in the UI
   - You should see the domain appear

2. **Test Domain Blocking:**
   - Click "Block Site" on a domain
   - Try to access it from the agent VM: `curl example.com`
   - Should fail or timeout

3. **Test Port Blocking:**
   - Find an active connection in Network tab
   - Click "Block Port"
   - Try to make a connection on that port
   - Should be blocked by firewall

## 🔐 Security Considerations

- **Root Access Required:** All blocking actions require root privileges
- **Firewall Persistence:** Port blocks should be made permanent if needed
- **DNS Bypassing:** Blocking via /etc/hosts can be bypassed by using IPs directly
- **Production Use:** Consider using proper DNS filtering (Pi-hole, corporate DNS) for production

## 📝 Future Enhancements

Potential improvements:
- [ ] Deep packet inspection for HTTPS SNI
- [ ] Integration with Pi-hole or DNS filtering
- [ ] Persistent firewall rules (save to nftables config)
- [ ] Whitelist common sites automatically
- [ ] Category-based blocking (social media, gaming, etc.)
- [ ] Bandwidth limiting per domain
- [ ] Historical site access logs
