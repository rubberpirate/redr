#!/bin/bash
# Quick Agent Update Script
# Updates the EDR agent on your VMs with the new malware detection code

echo "🚀 EDR Agent Update Script"
echo "=========================="
echo ""

# VM connection details - UPDATE THESE
VM1_USER="user"  # Change to your VM username
VM1_IP="192.168.x.x"  # Change to your VM IP
VM2_USER="user"  # Second VM username
VM2_IP="192.168.x.x"  # Second VM IP

AGENT_BINARY="/home/rubberpirate/redr/edr/agent/target/release/edr-agent"
REMOTE_PATH="/home/$VM1_USER/redr/target/release/"

echo "📦 Agent binary: $AGENT_BINARY"
echo ""

# Check if agent binary exists
if [ ! -f "$AGENT_BINARY" ]; then
    echo "❌ Error: Agent binary not found!"
    echo "Run: cd /home/rubberpirate/redr/edr/agent && cargo build --release"
    exit 1
fi

echo "Agent binary size: $(du -h $AGENT_BINARY | cut -f1)"
echo ""

# Function to update a VM
update_vm() {
    local vm_user=$1
    local vm_ip=$2
    local vm_name=$3
    
    echo "🔄 Updating $vm_name ($vm_user@$vm_ip)..."
    
    # Stop old agent
    echo "  Stopping old agent..."
    ssh "$vm_user@$vm_ip" "sudo pkill edr-agent" 2>/dev/null
    sleep 2
    
    # Copy new binary
    echo "  Copying new binary..."
    scp "$AGENT_BINARY" "$vm_user@$vm_ip:$REMOTE_PATH" || {
        echo "  ❌ Failed to copy to $vm_name"
        return 1
    }
    
    # Start new agent
    echo "  Starting new agent..."
    ssh "$vm_user@$vm_ip" "cd ~/redr && export EDR_SERVER_URL='http://172.16.0.2:8080' && export EDR_AGENT_TOKEN='local-dev-token' && export EDR_WATCH_PATHS='/home,/tmp' && sudo -E ./target/release/edr-agent &" &
    
    echo "  ✅ $vm_name updated!"
    echo ""
}

# Ask for confirmation
echo "This will:"
echo "  1. Stop the old agent on VMs"
echo "  2. Copy new agent binary"
echo "  3. Start new agent with malware detection"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

# Update VMs
echo ""
echo "🎯 Note: Update VM IPs and usernames in this script first!"
echo ""

# Uncomment and update these lines with your VM details:
# update_vm "$VM1_USER" "$VM1_IP" "VM1"
# update_vm "$VM2_USER" "$VM2_IP" "VM2"

echo "✅ Update complete!"
echo ""
echo "🧪 Test malware detection:"
echo "  1. SSH to your VM"
echo "  2. cp /path/to/ransomware.sh /tmp/"
echo "  3. Watch the EDR UI for malware alert!"
