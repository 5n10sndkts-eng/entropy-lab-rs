#!/bin/bash
# Build script for hashcat modules
# Integrates Entropy Lab RS modules into hashcat

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/../modules"
KERNELS_DIR="$SCRIPT_DIR/../kernels"
INCLUDE_DIR="$SCRIPT_DIR/../include"

# Check if hashcat path is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <path-to-hashcat>"
    echo "Example: $0 /home/user/hashcat"
    exit 1
fi

HASHCAT_DIR="$1"

if [ ! -d "$HASHCAT_DIR" ]; then
    echo "Error: Hashcat directory not found: $HASHCAT_DIR"
    exit 1
fi

if [ ! -f "$HASHCAT_DIR/Makefile" ]; then
    echo "Error: Not a valid hashcat directory (Makefile not found)"
    exit 1
fi

echo "=== Entropy Lab RS Hashcat Module Builder ==="
echo "Hashcat directory: $HASHCAT_DIR"
echo ""

# Backup existing files
echo "Creating backups..."
BACKUP_DIR="$HASHCAT_DIR/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Copy module files
echo "Copying module files..."
for module in "$MODULES_DIR"/module_*.c; do
    if [ -f "$module" ]; then
        module_name=$(basename "$module")
        echo "  - $module_name"
        
        # Backup if exists
        if [ -f "$HASHCAT_DIR/src/modules/$module_name" ]; then
            cp "$HASHCAT_DIR/src/modules/$module_name" "$BACKUP_DIR/"
        fi
        
        # Copy new module
        cp "$module" "$HASHCAT_DIR/src/modules/"
    fi
done

# Copy kernel files
echo "Copying kernel files..."
for kernel in "$KERNELS_DIR"/m*.cl; do
    if [ -f "$kernel" ]; then
        kernel_name=$(basename "$kernel")
        echo "  - $kernel_name"
        
        # Backup if exists
        if [ -f "$HASHCAT_DIR/OpenCL/$kernel_name" ]; then
            cp "$HASHCAT_DIR/OpenCL/$kernel_name" "$BACKUP_DIR/"
        fi
        
        # Copy new kernel
        cp "$kernel" "$HASHCAT_DIR/OpenCL/"
    fi
done

# Copy include files if any
if [ -d "$INCLUDE_DIR" ] && [ "$(ls -A $INCLUDE_DIR)" ]; then
    echo "Copying include files..."
    for include in "$INCLUDE_DIR"/*.cl; do
        if [ -f "$include" ]; then
            include_name=$(basename "$include")
            echo "  - $include_name"
            
            # Backup if exists
            if [ -f "$HASHCAT_DIR/OpenCL/$include_name" ]; then
                cp "$HASHCAT_DIR/OpenCL/$include_name" "$BACKUP_DIR/"
            fi
            
            # Copy new include
            cp "$include" "$HASHCAT_DIR/OpenCL/"
        fi
    done
fi

echo ""
echo "Files copied successfully!"
echo "Backup location: $BACKUP_DIR"
echo ""

# Build hashcat
echo "Building hashcat..."
cd "$HASHCAT_DIR"

# Clean previous build
echo "Running 'make clean'..."
make clean > /dev/null 2>&1

# Build
echo "Running 'make'..."
if make -j$(nproc); then
    echo ""
    echo "=== BUILD SUCCESSFUL ==="
    echo ""
    echo "Installed modules:"
    echo "  - m31900: Cake Wallet 2024 (Weak Electrum Entropy)"
    echo "  - m31901: Trust Wallet 2023 (MT19937 LSB Extraction)"
    echo ""
    echo "Test your installation:"
    echo "  $HASHCAT_DIR/hashcat -m 31900 --hash-info"
    echo "  $HASHCAT_DIR/hashcat -m 31901 --hash-info"
    echo ""
    echo "Run benchmarks:"
    echo "  $HASHCAT_DIR/hashcat -m 31900 -b"
    echo "  $HASHCAT_DIR/hashcat -m 31901 -b"
    echo ""
else
    echo ""
    echo "=== BUILD FAILED ==="
    echo ""
    echo "To restore previous files:"
    echo "  cp $BACKUP_DIR/* $HASHCAT_DIR/src/modules/"
    echo "  cp $BACKUP_DIR/* $HASHCAT_DIR/OpenCL/"
    echo ""
    exit 1
fi
