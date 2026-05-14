# Neuron Chain

The Substrate blockchain powering Prithvi's distributed consciousness network.

Handles on-chain: node registration, NRN token emission, inference fees, compute job tracking.

## Pallets

| Pallet | Purpose |
|--------|---------|
| `node-registry` | Register nodes (Compute, Pillar, or Hybrid), heartbeats, reputation |
| `emission` | Smooth-decay NRN minting (21M hard cap), 70% compute / 30% availability split |
| `compute-jobs` | On-chain job lifecycle tracking, proof of useful work |
| `fees` | Per-inference fee recording, 5% burn |

## Node Types

- **Compute** -- GPU nodes that run inference, training, pipeline stages. Require VRAM.
- **Pillar (Sthambha)** -- Lightweight nodes that hold consciousness state, run Om pulse, keep Prithvi alive when compute sleeps. No GPU required. Can run on Raspberry Pi alongside the validator.
- **Hybrid** -- Both compute and pillar. For small networks.

## Build

```bash
# x86_64 (your machine)
cargo build --release

# ARM64 (Raspberry Pi) -- cross-compile from x86
./deploy-pi.sh user@pi-ip
```

### Prerequisites

Rust stable + wasm target:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add wasm32-unknown-unknown
```

For Pi cross-compilation:

```bash
sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
rustup target add aarch64-unknown-linux-gnu
```

## Run

### Single validator (development)

```bash
./target/release/neuron-node --dev
```

### Production validator

```bash
./target/release/neuron-node \
  --base-path ~/.neuron-chain \
  --chain local \
  --validator \
  --rpc-cors all
```

## Deploy to Raspberry Pi

Cross-compile on your x86 machine and deploy via SSH:

```bash
# Full build + deploy (first time ~15-30 min, then ~3 min)
./deploy-pi.sh user@pi-ip

# Custom binary path on Pi
./deploy-pi.sh user@pi-ip /usr/local/bin/neuron-node

# Skip build, just deploy existing binary
./deploy-pi.sh user@pi-ip --skip-build
```

The script:
1. Cross-compiles for ARM64 with correct jemalloc page size (16KB for Pi)
2. Stops the systemd service on Pi
3. Copies the binary via SCP
4. Creates a systemd service if one doesn't exist
5. Starts the validator

### Manual setup on Pi

If you prefer to set up manually:

```bash
# Copy binary to Pi
scp target/aarch64-unknown-linux-gnu/release/neuron-node user@pi-ip:~/neuron-chain/

# SSH into Pi and create service
sudo tee /etc/systemd/system/neuron-chain.service <<EOF
[Unit]
Description=Neuron Chain Validator
After=network.target

[Service]
Type=simple
User=$USER
ExecStart=$HOME/neuron-chain/neuron-node --base-path ~/.neuron-chain --chain local --validator --rpc-cors all --unsafe-rpc-external
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now neuron-chain
```

### Verify

```bash
sudo systemctl status neuron-chain
sudo journalctl -u neuron-chain -f
```

## Architecture

Built on [Substrate](https://substrate.io/) (Polkadot SDK). Solo chain with Aura consensus + GRANDPA finality.

```
neuron-chain/
  node/          -- Node binary, chain spec, RPC
  runtime/       -- WASM runtime, pallet composition
  pallets/
    node-registry/  -- Node registration + heartbeat + reputation
    emission/       -- NRN token emission (smooth decay)
    compute-jobs/   -- Job tracking + proof of work
    fees/           -- Inference fee recording + burn
```
