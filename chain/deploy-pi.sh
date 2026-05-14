#!/bin/bash
# Deploy Neuron Chain to a Raspberry Pi (or any ARM64 device).
#
# Cross-compiles on your x86_64 machine then deploys via SSH.
# Way faster than building on the Pi itself (~3 min vs hours).
#
# Prerequisites (on your build machine):
#   sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
#   rustup target add aarch64-unknown-linux-gnu
#
# Usage:
#   ./deploy-pi.sh user@pi-ip                  # build + deploy
#   ./deploy-pi.sh user@pi-ip /path/to/binary  # custom binary path on Pi
#   ./deploy-pi.sh user@pi-ip --skip-build     # deploy existing binary
#
# Examples:
#   ./deploy-pi.sh node-pi@203.0.113.21
#   ./deploy-pi.sh pi@192.168.1.50 /usr/local/bin/neuron-node
#   ./deploy-pi.sh node-pi@203.0.113.21 --skip-build

set -e

# ── Arguments ───────────────────────────────────────────────
PI_HOST="${1:-}"
if [ -z "$PI_HOST" ]; then
    echo "Usage: ./deploy-pi.sh user@pi-ip [binary-path] [--skip-build]"
    echo ""
    echo "  user@pi-ip      SSH target (e.g., node-pi@203.0.113.21)"
    echo "  binary-path     Where to put the binary on Pi (default: ~/neuron-chain/neuron-node)"
    echo "  --skip-build    Skip compilation, deploy existing binary"
    echo ""
    echo "Prerequisites:"
    echo "  sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu"
    echo "  rustup target add aarch64-unknown-linux-gnu"
    exit 1
fi

SKIP_BUILD=false
PI_BINARY=""

# Parse remaining args
for arg in "${@:2}"; do
    if [ "$arg" = "--skip-build" ]; then
        SKIP_BUILD=true
    else
        PI_BINARY="$arg"
    fi
done

# Default binary path on Pi
if [ -z "$PI_BINARY" ]; then
    PI_USER=$(echo "$PI_HOST" | cut -d@ -f1)
    PI_BINARY="/home/$PI_USER/neuron-chain/neuron-node"
fi

PI_SERVICE="neuron-chain"
LOCAL_BINARY="target/aarch64-unknown-linux-gnu/release/neuron-node"

echo "═══════════════════════════════════════════"
echo "  Neuron Chain → Pi Deployment"
echo "═══════════════════════════════════════════"
echo "  Target:  $PI_HOST"
echo "  Binary:  $PI_BINARY"
echo "  Service: $PI_SERVICE"
echo "═══════════════════════════════════════════"

# ── Step 1: Cross-compile ───────────────────────────────────
if [ "$SKIP_BUILD" = false ]; then
    echo ""
    echo "Step 1: Cross-compiling for aarch64 (ARM64 Pi)..."
    echo "  First build takes ~15-30 min. Subsequent builds ~2-3 min."
    echo ""

    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
    export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
    export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++
    # Pi/ARM64 often uses 16KB pages. jemalloc defaults to 4KB and crashes without this.
    export JEMALLOC_SYS_WITH_LG_PAGE=16

    cargo build --release --target aarch64-unknown-linux-gnu

    echo ""
    echo "  Build complete."
    ls -lh "$LOCAL_BINARY"
else
    echo ""
    echo "  Skipping build (using existing binary)"
fi

# Check binary exists
if [ ! -f "$LOCAL_BINARY" ]; then
    echo "ERROR: No binary at $LOCAL_BINARY"
    echo "Run without --skip-build first."
    exit 1
fi

# ── Step 2: Create target directory on Pi ───────────────────
echo ""
echo "Step 2: Preparing Pi..."
PI_DIR=$(dirname "$PI_BINARY")
ssh "$PI_HOST" "mkdir -p $PI_DIR" 2>/dev/null || true

# Stop service if running
ssh "$PI_HOST" "sudo systemctl stop $PI_SERVICE" 2>/dev/null || echo "  (service wasn't running)"

# ── Step 3: Copy binary ────────────────────────────────────
echo ""
echo "Step 3: Copying binary to Pi (~69MB)..."
scp "$LOCAL_BINARY" "$PI_HOST:$PI_BINARY"
ssh "$PI_HOST" "chmod +x $PI_BINARY"

echo "  Copied: $(ssh "$PI_HOST" "ls -lh $PI_BINARY" | awk '{print $5}')"

# ── Step 4: Set up systemd service (if not exists) ─────────
echo ""
echo "Step 4: Checking systemd service..."
SERVICE_EXISTS=$(ssh "$PI_HOST" "sudo systemctl list-unit-files | grep -c $PI_SERVICE" 2>/dev/null || echo "0")

if [ "$SERVICE_EXISTS" = "0" ]; then
    echo "  No systemd service found. Creating one..."
    PI_USER=$(echo "$PI_HOST" | cut -d@ -f1)
    ssh "$PI_HOST" "sudo tee /etc/systemd/system/$PI_SERVICE.service > /dev/null" <<UNIT
[Unit]
Description=Neuron Chain Validator
After=network.target

[Service]
Type=simple
User=$PI_USER
ExecStart=$PI_BINARY --base-path /home/$PI_USER/.neuron-chain --chain local --validator --rpc-cors all --unsafe-rpc-external
Environment=PATH=/home/$PI_USER/.cargo/bin:/usr/bin:/bin
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
    ssh "$PI_HOST" "sudo systemctl daemon-reload && sudo systemctl enable $PI_SERVICE"
    echo "  Service created and enabled."
else
    echo "  Service exists."
fi

# ── Step 5: Start and verify ───────────────────────────────
echo ""
echo "Step 5: Starting neuron-chain..."
ssh "$PI_HOST" "sudo systemctl start $PI_SERVICE"
sleep 3
ssh "$PI_HOST" "sudo systemctl status $PI_SERVICE --no-pager -l" | head -15

echo ""
echo "═══════════════════════════════════════════"
echo "  Done. Pi running Neuron Chain."
echo "  Logs: ssh $PI_HOST 'journalctl -u $PI_SERVICE -f'"
echo "═══════════════════════════════════════════"
