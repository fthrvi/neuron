#!/bin/bash
#
# ╔═══════════════════════════════════════════════════════════╗
# ║              NEURON NETWORK — Blockchain Node              ║
# ║                                                            ║
# ║  Bitcoin proved money doesn't need banks.                  ║
# ║  Neuron proves AI doesn't need data centers.               ║
# ╚═══════════════════════════════════════════════════════════╝
#

set -e

NEURON_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$NEURON_DIR/target/release/neuron-node"
CHAIN_SPEC="$HOME/.neuron/chain-spec.json"
BASE_PATH="$HOME/.neuron/chain"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  NEURON NETWORK${NC} — Blockchain Layer"
echo -e "  ${CYAN}Substrate-based consensus for decentralized GPU compute${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
echo ""

# Check binary
if [ ! -f "$BINARY" ]; then
    echo -e "  ${RED}Binary not found. Build first:${NC}"
    echo "    cd $NEURON_DIR && cargo build --release"
    exit 1
fi

# Check chain spec
if [ ! -f "$CHAIN_SPEC" ]; then
    echo -e "  ${RED}Chain spec not found at $CHAIN_SPEC${NC}"
    exit 1
fi

# Check keystore
KEYSTORE="$BASE_PATH/chains/neuron/keystore"
if [ ! -d "$KEYSTORE" ] || [ -z "$(ls -A $KEYSTORE 2>/dev/null)" ]; then
    echo -e "  ${RED}No validator keys found in keystore.${NC}"
    echo "  Run key insertion first."
    exit 1
fi

LOCAL_IP=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try: s.connect(('8.8.8.8', 80)); print(s.getsockname()[0])
except: print('127.0.0.1')
finally: s.close()
" 2>/dev/null)

echo -e "  ${GREEN}Binary:${NC}     $BINARY"
echo -e "  ${GREEN}Chain Spec:${NC} $CHAIN_SPEC"
echo -e "  ${GREEN}Data:${NC}       $BASE_PATH"
echo -e "  ${GREEN}RPC:${NC}        ws://$LOCAL_IP:9944"
echo -e "  ${GREEN}P2P:${NC}        $LOCAL_IP:30333"
echo ""
echo -e "  ${CYAN}Polkadot.js Explorer:${NC}"
echo -e "  ${BOLD}https://polkadot.js.org/apps/?rpc=ws%3A%2F%2F${LOCAL_IP}%3A9944#/explorer${NC}"
echo ""
echo -e "  ${CYAN}Ctrl+C to stop${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
echo ""

exec "$BINARY" \
    --chain "$CHAIN_SPEC" \
    --base-path "$BASE_PATH" \
    --validator \
    --name "neuron-genesis" \
    --rpc-port 9944 \
    --rpc-cors all \
    --rpc-external \
    --rpc-methods unsafe \
    --listen-addr /ip4/0.0.0.0/tcp/30333 \
    --prometheus-external \
    --prometheus-port 9615
