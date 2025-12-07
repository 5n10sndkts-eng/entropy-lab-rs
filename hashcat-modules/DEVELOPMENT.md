# Hashcat Module Development Guide

This document provides detailed instructions for developing and integrating the Entropy Lab RS hashcat modules.

## Overview

Hashcat modules consist of two main components:
1. **Host Module** (C file): Defines the hash mode, parsing, and encoding logic
2. **OpenCL Kernels**: GPU compute kernels for the actual cracking work

## Directory Structure

```
hashcat-modules/
├── README.md                    # Main documentation
├── DEVELOPMENT.md               # This file
├── modules/                     # Host-side C modules
│   ├── module_31900.c          # Cake Wallet module
│   ├── module_31901.c          # Trust Wallet module
│   └── module_319XX.c          # Additional modules
├── kernels/                     # OpenCL GPU kernels
│   ├── m31900_a3-pure.cl       # Cake Wallet kernel (attack mode 3)
│   ├── m31901_a3-pure.cl       # Trust Wallet kernel
│   └── m319XX_*.cl             # Additional kernels
├── include/                     # Shared include files
│   ├── inc_bip39_helpers.cl    # BIP39 utilities
│   ├── inc_bip32.cl            # BIP32 derivation
│   └── inc_mt19937.cl          # MT19937 PRNG
├── scripts/                     # Helper scripts
│   ├── build.sh                # Build script
│   └── test.sh                 # Test script
└── test-vectors/                # Test cases
    ├── m31900.txt              # Cake Wallet test vectors
    └── m31901.txt              # Trust Wallet test vectors
```

## Module Number Assignment

We use the 31900-31999 range for cryptocurrency wallet vulnerabilities:

| Module | Number | Description |
|--------|--------|-------------|
| Cake Wallet 2024 | 31900 | Weak Electrum seed entropy |
| Trust Wallet 2023 | 31901 | MT19937 LSB extraction |
| Milk Sad (Libbitcoin) | 31902 | MT19937 timestamp-based |
| Mobile Sensor Entropy | 31903 | Sensor-based PRNG |
| Profanity | 31904 | Weak private key generation |
| Cake Wallet Dart PRNG | 31905 | Time-based Dart PRNG |

## Creating a New Module

### Step 1: Create Host Module (module_XXXXX.c)

```c
#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"

// Define module constants
static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_5; // For 20-byte Hash160
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Your Module Name";
static const u64   KERN_TYPE      = 31XXX; // Your module number
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_HASH_COPY
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;

// Define hash format signature
static const char *SIGNATURE_YOUR_MODULE = "$yourmodule$";

// Define structures
typedef struct your_module
{
  // Module-specific data
  u32 target_hash160[5];
  // Additional fields as needed

} your_module_t;

typedef struct your_module_tmp
{
  // Temporary computation data
  u64 dgst[8];
  u64 out[8];

} your_module_tmp_t;

// Implement required functions
int module_hash_decode (...)
{
  // Parse hash from string format
}

int module_hash_encode (...)
{
  // Encode hash to string format
}

u64 module_esalt_size (...)
{
  return sizeof (your_module_t);
}

u64 module_tmp_size (...)
{
  return sizeof (your_module_tmp_t);
}

void module_init (module_ctx_t *module_ctx)
{
  // Register all module functions
}
```

### Step 2: Create OpenCL Kernel (mXXXXX_a3-pure.cl)

```c
#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
// Include necessary hash/crypto functions
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#endif

// Define same structures as module
typedef struct your_module { ... } your_module_t;
typedef struct your_module_tmp { ... } your_module_tmp_t;

// Initialization kernel
KERNEL_FQ void mXXXXX_init (KERN_ATTR_TMPS_ESALT (your_module_tmp_t, your_module_t))
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;
  
  // Parse input
  // Generate initial values
  // Store in tmp buffer
}

// Loop kernel (for iterative algorithms like PBKDF2)
KERNEL_FQ void mXXXXX_loop (KERN_ATTR_TMPS_ESALT (your_module_tmp_t, your_module_t))
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;
  
  // Perform iterative computation
}

// Comparison kernel
KERNEL_FQ void mXXXXX_comp (KERN_ATTR_TMPS_ESALT (your_module_tmp_t, your_module_t))
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;
  
  // Final computation
  // Compare result against target
  // Mark if match found
}
```

### Step 3: Create Test Vectors

Create `test-vectors/mXXXXX.txt` with known good hash/password pairs:

```
password:$yourmodule$targethash
123456:$yourmodule$sometargethash
```

## Integration with Hashcat

### Option 1: Direct Integration

1. Copy module file:
```bash
cp hashcat-modules/modules/module_31900.c /path/to/hashcat/src/modules/
```

2. Copy kernel files:
```bash
cp hashcat-modules/kernels/m31900*.cl /path/to/hashcat/OpenCL/
```

3. Copy include files (if any):
```bash
cp hashcat-modules/include/*.cl /path/to/hashcat/OpenCL/
```

4. Rebuild hashcat:
```bash
cd /path/to/hashcat
make clean
make
```

### Option 2: Standalone Usage

Use the provided scripts to test modules independently:

```bash
./hashcat-modules/scripts/test_module.sh 31900 test-vectors/m31900.txt
```

## Testing

### Unit Testing

Test individual components:

```bash
# Test hash parsing
echo '$cakewallet$bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh' | \
  hashcat -m 31900 --hash-info

# Test with known password
hashcat -m 31900 -a 3 hash.txt ?d?d?d?d
```

### Performance Testing

Benchmark the module:

```bash
hashcat -m 31900 -b
```

Expected performance metrics:
- RTX 3090: ~50-100 MH/s (varies by module complexity)
- RTX 4090: ~80-150 MH/s
- AMD RX 7900 XTX: ~60-120 MH/s

## Optimization Tips

### 1. Memory Access Patterns

```c
// Good: Coalesced access
for (int i = 0; i < 16; i++)
{
  output[gid * 16 + i] = data[i];
}

// Bad: Strided access
for (int i = 0; i < 16; i++)
{
  output[i * total_threads + gid] = data[i];
}
```

### 2. Loop Unrolling

```c
// Manually unroll small loops
#pragma unroll
for (int i = 0; i < 8; i++)
{
  result[i] = compute(input[i]);
}
```

### 3. Register Usage

Minimize register pressure to increase occupancy:

```c
// Use local memory for large arrays
__local u32 shared_data[256];

// Share data across work-group
barrier(CLK_LOCAL_MEM_FENCE);
```

### 4. Vectorization

Use vector types when possible:

```c
uint4 data = vload4(0, input);
data = data + (uint4)(1, 2, 3, 4);
vstore4(data, 0, output);
```

## Common Pitfalls

### 1. Endianness Issues

Bitcoin uses big-endian for many operations:

```c
// Correct: Swap for big-endian
u32 value = byte_swap_32(input);

// Wrong: Direct use
u32 value = input;
```

### 2. Checksum Calculation

BIP39 requires proper checksum:

```c
// Correct: Use first N bits of SHA-256
u32 checksum = (sha256_hash[0] >> (32 - checksum_bits)) & mask;

// Wrong: Use whole bytes
u32 checksum = sha256_hash[0] & 0xFF;
```

### 3. Derivation Paths

Different paths for different standards:

```c
// BIP44: m/44'/0'/0'/0/0
// BIP49: m/49'/0'/0'/0/0
// BIP84: m/84'/0'/0'/0/0
// Electrum: m/0'/0/0
```

## Debugging

### Enable Debug Output

```c
#ifdef DEBUG
printf("gid=%lu, value=%u\n", gid, value);
#endif
```

### Test on CPU First

Use `-D DEBUG` flag to compile for CPU execution:

```bash
hashcat -m 31900 -D 1 hash.txt wordlist.txt
```

### Verify Intermediate Values

Compare against reference implementation:

```bash
# Use the Rust implementation as reference
cargo run --release -- cake-wallet --limit 10
```

## Performance Profiling

### Using hashcat's built-in profiler

```bash
hashcat -m 31900 --speed-only
```

### Using GPU profilers

NVIDIA:
```bash
nvprof hashcat -m 31900 hash.txt wordlist.txt
```

AMD:
```bash
rocprof hashcat -m 31900 hash.txt wordlist.txt
```

## Contributing

When contributing new modules:

1. Follow the existing code style
2. Add comprehensive comments
3. Include test vectors
4. Document the vulnerability
5. Provide performance benchmarks
6. Update this guide

## References

- [Hashcat Source Code](https://github.com/hashcat/hashcat)
- [OpenCL Programming Guide](https://www.khronos.org/opencl/)
- [BIP39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [secp256k1 Documentation](https://github.com/bitcoin-core/secp256k1)
- [Milk Sad Disclosure](https://milksad.info/)

## Support

For issues or questions:
- Open an issue on GitHub
- Check existing test vectors
- Review the Rust implementation for reference
- Consult hashcat forums for OpenCL optimization tips

## License

MIT License - See LICENSE file for details
