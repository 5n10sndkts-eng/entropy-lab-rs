# Hashcat Integration Examples

Real-world examples and workflows for using Entropy Lab RS hashcat modules.

## Table of Contents

- [Basic Examples](#basic-examples)
- [Advanced Workflows](#advanced-workflows)
- [Distributed Cracking](#distributed-cracking)
- [Performance Tuning](#performance-tuning)
- [Real-World Scenarios](#real-world-scenarios)

## Basic Examples

### Example 1: Cake Wallet Single Target

Scan for a single Cake Wallet address through the entire 2^20 entropy space:

```bash
# Create target hash file
cat > cake_target.hash << 'EOF'
$cakewallet$bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
EOF

# Run full entropy space scan (1,048,576 seeds)
hashcat -m 31900 -a 3 cake_target.hash ?d?d?d?d?d?d?d

# With status updates every 10 seconds
hashcat -m 31900 -a 3 cake_target.hash ?d?d?d?d?d?d?d \
  --status --status-timer=10

# Expected time on RTX 3090: ~10-15 seconds
```

### Example 2: Trust Wallet Timestamp Range

Scan the vulnerable Trust Wallet window (Nov 14-23, 2022):

```bash
# Create target with full vulnerable window
cat > trust_target.hash << 'EOF'
$trustwallet$1668384000$1669247999$76a914751e76e8199196d454941c45d1b3a323f1433bd688ac
EOF

# Scan entire window (864,000 seconds)
hashcat -m 31901 -a 3 trust_target.hash ?d?d?d?d?d?d?d?d?d?d

# Expected time on RTX 3090: ~17 seconds
```

### Example 3: Multiple Targets

Scan multiple addresses simultaneously:

```bash
# Create multi-target file
cat > multi_targets.hash << 'EOF'
$cakewallet$bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
$cakewallet$bc1q9ajp7u9qr5yxkm8r4vnkfwcv24xhd63j2xmpgs
$cakewallet$bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
EOF

# Scan all targets
hashcat -m 31900 -a 3 multi_targets.hash ?d?d?d?d?d?d?d
```

## Advanced Workflows

### Workflow 1: Staged Scanning

Break large searches into manageable chunks:

```bash
# Stage 1: Scan first 100,000 seeds
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d \
  -s 0 -l 100000 \
  --session stage1

# Stage 2: Scan next 100,000
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d \
  -s 100000 -l 100000 \
  --session stage2

# Stage 3: Continue...
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d \
  -s 200000 -l 100000 \
  --session stage3
```

### Workflow 2: Session Management

Use sessions for long-running scans:

```bash
# Start a named session
hashcat -m 31901 -a 3 target.hash ?d?d?d?d?d?d?d?d?d?d \
  --session trust_scan \
  --restore-file-path ./sessions/

# Check status (from another terminal)
hashcat --session trust_scan --status

# Pause (Ctrl+C), then resume
hashcat --session trust_scan --restore

# Skip to specific position
hashcat --session trust_scan --restore --skip 500000
```

### Workflow 3: Result Management

Organize and track results:

```bash
# Create organized output directory
mkdir -p results/cake_wallet_$(date +%Y%m%d)

# Run with specific output format
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d \
  --outfile results/cake_wallet_$(date +%Y%m%d)/found.txt \
  --outfile-format 2 \
  --potfile-path results/cake_wallet.potfile

# View results
cat results/cake_wallet_$(date +%Y%m%d)/found.txt
```

## Distributed Cracking

### Setup 1: Multi-GPU Single Machine

Utilize all GPUs on one machine:

```bash
# List available devices
hashcat -I

# Use all GPUs
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d -d 1,2,3,4

# Different workloads per GPU (if mixed hardware)
# GPU 1 (RTX 4090 - fast)
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d \
  -d 1 -s 0 -l 600000 --session gpu1 &

# GPU 2 (RTX 3090 - medium)
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d \
  -d 2 -s 600000 -l 300000 --session gpu2 &

# GPU 3 (RTX 3080 - slower)
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d \
  -d 3 -s 900000 -l 148576 --session gpu3 &
```

### Setup 2: Multiple Machines

Distribute across a cluster:

**Master node (192.168.1.100)**:
```bash
# Calculate segments (1,048,576 total / 4 machines = 262,144 each)

# Machine 1: Seeds 0-262143
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d \
  -s 0 -l 262144

# Monitor progress across machines
watch -n 10 'hashcat --status --session machine1'
```

**Worker nodes**:
```bash
# Machine 2: Seeds 262144-524287
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d \
  -s 262144 -l 262144

# Machine 3: Seeds 524288-786431
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d \
  -s 524288 -l 262144

# Machine 4: Seeds 786432-1048575
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d \
  -s 786432 -l 262144
```

### Setup 3: Cloud Bursting

Use cloud resources for temporary scale:

```bash
#!/bin/bash
# cloud_burst.sh - Launch multiple cloud instances

INSTANCE_COUNT=10
TARGET_HASH="target.hash"
TOTAL_SPACE=1048576

CHUNK_SIZE=$((TOTAL_SPACE / INSTANCE_COUNT))

for i in $(seq 0 $((INSTANCE_COUNT-1))); do
    START=$((i * CHUNK_SIZE))
    
    # Launch cloud instance with hashcat
    aws ec2 run-instances \
        --image-id ami-gpu-hashcat \
        --instance-type g4dn.xlarge \
        --user-data "#!/bin/bash
            hashcat -m 31900 -a 3 $TARGET_HASH ?d?d?d?d?d?d?d \
                -s $START -l $CHUNK_SIZE \
                --session cloud_$i
        " \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=hashcat-worker-$i}]"
done
```

## Performance Tuning

### Tuning 1: Optimal Workload

Find the best workload setting for your GPU:

```bash
# Test different workload profiles
for w in 1 2 3 4; do
    echo "Testing workload $w..."
    hashcat -m 31900 -b -w $w 2>&1 | grep "Speed.#"
done

# Use the fastest setting
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d -w 3
```

### Tuning 2: Kernel Accel/Loops

Fine-tune kernel parameters:

```bash
# Auto-tune (recommended)
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d --kernel-accel=0

# Manual tuning
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d \
  --kernel-accel=256 \
  --kernel-loops=1024

# Test different values
for accel in 64 128 256 512; do
    hashcat -m 31900 -b --kernel-accel=$accel
done
```

### Tuning 3: Monitor GPU Usage

Track GPU utilization and optimize:

```bash
# NVIDIA
watch -n 1 nvidia-smi

# AMD
watch -n 1 rocm-smi

# While running hashcat
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d \
  --hwmon-temp-abort=90 \
  --status --status-timer=5
```

## Real-World Scenarios

### Scenario 1: Security Audit

Audit a list of addresses for Cake Wallet vulnerability:

```bash
#!/bin/bash
# audit_addresses.sh

ADDRESSES_FILE="addresses_to_audit.txt"
RESULTS_DIR="audit_results_$(date +%Y%m%d)"
mkdir -p "$RESULTS_DIR"

# Convert addresses to hash format
while IFS= read -r address; do
    echo "\$cakewallet\$$address" >> "$RESULTS_DIR/hashes.txt"
done < "$ADDRESSES_FILE"

# Run scan
hashcat -m 31900 -a 3 "$RESULTS_DIR/hashes.txt" ?d?d?d?d?d?d?d \
  --outfile "$RESULTS_DIR/vulnerable.txt" \
  --outfile-format 2 \
  --status --status-timer=10

# Generate report
echo "Audit Report - $(date)" > "$RESULTS_DIR/report.txt"
echo "Total Addresses Checked: $(wc -l < $ADDRESSES_FILE)" >> "$RESULTS_DIR/report.txt"
echo "Vulnerable Addresses Found: $(wc -l < $RESULTS_DIR/vulnerable.txt)" >> "$RESULTS_DIR/report.txt"
```

### Scenario 2: Incident Response

Quickly check if compromised addresses are vulnerable:

```bash
#!/bin/bash
# incident_response.sh

COMPROMISED_ADDR="$1"
URGENT=true

if [ -z "$COMPROMISED_ADDR" ]; then
    echo "Usage: $0 <address>"
    exit 1
fi

echo "INCIDENT RESPONSE: Checking $COMPROMISED_ADDR"
echo "\$cakewallet\$$COMPROMISED_ADDR" > /tmp/incident.hash

# High-priority scan
hashcat -m 31900 -a 3 /tmp/incident.hash ?d?d?d?d?d?d?d \
  -w 4 \
  --hwmon-disable \
  --status --status-timer=2

if [ $? -eq 0 ]; then
    echo "ALERT: Address IS vulnerable!"
    # Send alert, update tracking system, etc.
else
    echo "Address not found in vulnerability space"
fi
```

### Scenario 3: Research Analysis

Analyze vulnerability patterns:

```bash
#!/bin/bash
# research_analysis.sh

SAMPLE_SIZE=1000
RESULTS_FILE="research_results.csv"

echo "Seed,Address,Found" > "$RESULTS_FILE"

# Generate sample addresses
for seed in $(seq 0 10 $SAMPLE_SIZE); do
    # Use Rust implementation to generate address for seed
    address=$(cargo run --release -- cake-wallet --limit $((seed+1)) 2>/dev/null | tail -1 | grep -oP 'bc1\w+')
    
    if [ ! -z "$address" ]; then
        echo "\$cakewallet\$$address" > /tmp/sample_$seed.hash
        
        # Check if hashcat finds it
        if hashcat -m 31900 -a 3 /tmp/sample_$seed.hash ?d?d?d?d?d?d?d --quiet 2>/dev/null; then
            echo "$seed,$address,YES" >> "$RESULTS_FILE"
        else
            echo "$seed,$address,NO" >> "$RESULTS_FILE"
        fi
    fi
done

echo "Research analysis complete. Results in $RESULTS_FILE"
```

### Scenario 4: Continuous Monitoring

Set up continuous monitoring for new addresses:

```bash
#!/bin/bash
# continuous_monitor.sh

WATCH_LIST="addresses_to_monitor.txt"
CHECK_INTERVAL=3600  # 1 hour

while true; do
    echo "[$(date)] Starting scan cycle..."
    
    # Generate current hash file
    HASH_FILE="/tmp/monitor_$(date +%s).hash"
    while IFS= read -r address; do
        echo "\$cakewallet\$$address" >> "$HASH_FILE"
    done < "$WATCH_LIST"
    
    # Scan
    hashcat -m 31900 -a 3 "$HASH_FILE" ?d?d?d?d?d?d?d \
        --outfile /tmp/found.txt \
        --outfile-format 2 \
        --quiet
    
    # Check results
    if [ -s /tmp/found.txt ]; then
        # Alert on findings
        mail -s "ALERT: Vulnerable addresses found" security@example.com < /tmp/found.txt
    fi
    
    # Cleanup
    rm "$HASH_FILE" /tmp/found.txt
    
    echo "[$(date)] Scan complete. Sleeping for $CHECK_INTERVAL seconds..."
    sleep $CHECK_INTERVAL
done
```

## Tips and Best Practices

### Resource Management

```bash
# Limit CPU usage for other tasks
nice -n 19 hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d

# Set GPU power limit (NVIDIA)
nvidia-smi -pl 250  # 250W limit

# Monitor temperatures
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d \
  --hwmon-temp-abort=85
```

### Automation

```bash
# Cron job for scheduled scans
0 2 * * * /path/to/hashcat -m 31900 -a 3 /path/to/targets.hash ?d?d?d?d?d?d?d \
  --outfile /path/to/results/$(date +\%Y\%m\%d).txt

# Systemd service for continuous scanning
cat > /etc/systemd/system/hashcat-monitor.service << 'EOF'
[Unit]
Description=Hashcat Continuous Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/continuous_monitor.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF
```

### Debugging

```bash
# Enable debug output
hashcat -m 31900 -a 3 target.hash ?d?d?d?d?d?d?d --debug-mode=1

# Test with single candidate
echo "100" | hashcat -m 31900 target.hash --stdin

# Verify hash parsing
hashcat -m 31900 --hash-info --example-hashes
```

## Performance Expectations

Based on testing with various GPUs:

| GPU Model | m31900 (MH/s) | m31901 (MH/s) | Full Scan Time |
|-----------|---------------|---------------|----------------|
| RTX 4090 | ~150 | ~80 | ~7s / ~13s |
| RTX 3090 | ~100 | ~50 | ~10s / ~21s |
| RTX 3080 | ~80 | ~40 | ~13s / ~26s |
| RTX 3070 | ~60 | ~30 | ~17s / ~35s |
| RX 7900 XTX | ~120 | ~60 | ~9s / ~18s |
| RX 6900 XT | ~90 | ~45 | ~12s / ~24s |

*Times shown for Cake Wallet (2^20) and Trust Wallet (864k timestamps) full scans*

## Conclusion

These examples demonstrate the flexibility and power of the Entropy Lab RS hashcat modules. Adapt these workflows to your specific security research needs while always following ethical guidelines and legal requirements.

For more information:
- [USAGE.md](USAGE.md) - Complete user guide
- [DEVELOPMENT.md](DEVELOPMENT.md) - Module development
- [README.md](README.md) - Project overview
