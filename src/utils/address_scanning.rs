use anyhow::Result;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network};
use std::str::FromStr;

/// Standard BIP derivation paths
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivationPathType {
    /// BIP44: m/44'/0'/0'/0/x (Legacy P2PKH)
    BIP44,
    /// BIP49: m/49'/0'/0'/0/x (Nested SegWit P2SH-P2WPKH)
    BIP49,
    /// BIP84: m/84'/0'/0'/0/x (Native SegWit P2WPKH)
    BIP84,
    /// BIP86: m/86'/0'/0'/0/x (Taproot P2TR)
    BIP86,
    /// Electrum: m/0'/0/x (Electrum standard)
    Electrum,
}

impl DerivationPathType {
    /// Get the purpose number for this path type
    pub fn purpose(&self) -> u32 {
        match self {
            DerivationPathType::BIP44 => 44,
            DerivationPathType::BIP49 => 49,
            DerivationPathType::BIP84 => 84,
            DerivationPathType::BIP86 => 86,
            DerivationPathType::Electrum => 0,
        }
    }

    /// Get the full derivation path for a given index
    /// account=0, change=0 (external addresses, not change addresses)
    pub fn path(&self, index: u32) -> String {
        match self {
            DerivationPathType::Electrum => format!("m/0'/0/{}", index),
            _ => format!("m/{}'/{}'/{}'/{}/{}", self.purpose(), 0, 0, 0, index),
        }
    }

    /// Get all standard path types (BIP44/49/84)
    pub fn all_standard() -> Vec<DerivationPathType> {
        vec![
            DerivationPathType::BIP44,
            DerivationPathType::BIP49,
            DerivationPathType::BIP84,
        ]
    }

    /// Get all path types including Taproot
    pub fn all_with_taproot() -> Vec<DerivationPathType> {
        vec![
            DerivationPathType::BIP44,
            DerivationPathType::BIP49,
            DerivationPathType::BIP84,
            DerivationPathType::BIP86,
        ]
    }

    /// Get display name for path type
    pub fn name(&self) -> &'static str {
        match self {
            DerivationPathType::BIP44 => "BIP44 (Legacy P2PKH)",
            DerivationPathType::BIP49 => "BIP49 (Nested SegWit)",
            DerivationPathType::BIP84 => "BIP84 (Native SegWit)",
            DerivationPathType::BIP86 => "BIP86 (Taproot)",
            DerivationPathType::Electrum => "Electrum Standard",
        }
    }
}

/// Configuration for address scanning
#[derive(Debug, Clone)]
pub struct AddressScanConfig {
    /// Maximum address index to check (default: 0)
    pub max_index: u32,
    /// Derivation path types to check
    pub path_types: Vec<DerivationPathType>,
    /// Network to use
    pub network: Network,
    /// Include change addresses (m/.../.../1/x) in addition to external (m/.../.../0/x)
    pub include_change: bool,
}

impl Default for AddressScanConfig {
    fn default() -> Self {
        Self {
            max_index: 0,
            path_types: vec![DerivationPathType::BIP44],
            network: Network::Bitcoin,
            include_change: false,
        }
    }
}

impl AddressScanConfig {
    /// Create config for single address (index 0, single path)
    pub fn single_address(path_type: DerivationPathType) -> Self {
        Self {
            max_index: 0,
            path_types: vec![path_type],
            network: Network::Bitcoin,
            include_change: false,
        }
    }

    /// Create config for extended indices (0..max_index)
    pub fn extended_indices(path_type: DerivationPathType, max_index: u32) -> Self {
        Self {
            max_index,
            path_types: vec![path_type],
            network: Network::Bitcoin,
            include_change: false,
        }
    }

    /// Create config for multi-path scanning (all standard paths, index 0)
    pub fn multi_path() -> Self {
        Self {
            max_index: 0,
            path_types: DerivationPathType::all_standard(),
            network: Network::Bitcoin,
            include_change: false,
        }
    }

    /// Create config for comprehensive scanning (multi-path + extended indices)
    pub fn comprehensive(max_index: u32) -> Self {
        Self {
            max_index,
            path_types: DerivationPathType::all_standard(),
            network: Network::Bitcoin,
            include_change: false,
        }
    }

    /// Total number of addresses that will be generated
    pub fn total_addresses(&self) -> usize {
        let indices = (self.max_index + 1) as usize;
        let chains = if self.include_change { 2 } else { 1 };
        self.path_types.len() * indices * chains
    }
}

/// A generated address with its derivation information
#[derive(Debug, Clone)]
pub struct DerivedAddress {
    /// The Bitcoin address
    pub address: Address,
    /// The derivation path used
    pub path: String,
    /// The path type
    pub path_type: DerivationPathType,
    /// The address index
    pub index: u32,
    /// Whether this is a change address
    pub is_change: bool,
}

/// Generate all addresses for a given seed according to the scan configuration
pub fn generate_addresses(
    root: &Xpriv,
    config: &AddressScanConfig,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Result<Vec<DerivedAddress>> {
    let mut addresses = Vec::new();

    for path_type in &config.path_types {
        // Generate addresses for external chain (change=0)
        for index in 0..=config.max_index {
            let path_str = path_type.path(index);
            let address = derive_address_at_path(root, &path_str, *path_type, config.network, secp)?;

            addresses.push(DerivedAddress {
                address,
                path: path_str,
                path_type: *path_type,
                index,
                is_change: false,
            });
        }

        // Generate addresses for change chain (change=1) if enabled
        if config.include_change {
            for index in 0..=config.max_index {
                let path_str = if *path_type == DerivationPathType::Electrum {
                    format!("m/0'/1/{}", index)
                } else {
                    format!("m/{}'/{}'/{}'/{}/{}", path_type.purpose(), 0, 0, 1, index)
                };

                let address = derive_address_at_path(root, &path_str, *path_type, config.network, secp)?;

                addresses.push(DerivedAddress {
                    address,
                    path: path_str,
                    path_type: *path_type,
                    index,
                    is_change: true,
                });
            }
        }
    }

    Ok(addresses)
}

/// Derive a single address at a specific path
fn derive_address_at_path(
    root: &Xpriv,
    path: &str,
    path_type: DerivationPathType,
    network: Network,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Result<Address> {
    let derivation_path = DerivationPath::from_str(path)?;
    let child = root.derive_priv(secp, &derivation_path)?;
    let pubkey = child.to_keypair(secp).public_key();

    // Determine address type based on derivation path
    let address = match path_type {
        DerivationPathType::BIP44 => {
            // Legacy P2PKH
            Address::p2pkh(bitcoin::PublicKey::new(pubkey), network)
        }
        DerivationPathType::BIP49 => {
            // Nested SegWit P2SH-P2WPKH
            let compressed = bitcoin::CompressedPublicKey(pubkey);
            Address::p2shwpkh(&compressed, network)
        }
        DerivationPathType::BIP84 => {
            // Native SegWit P2WPKH
            let compressed = bitcoin::CompressedPublicKey(pubkey);
            Address::p2wpkh(&compressed, network)
        }
        DerivationPathType::BIP86 => {
            // Taproot P2TR
            let x_only = bitcoin::key::XOnlyPublicKey::from(pubkey);
            Address::p2tr(secp, x_only, None, network)
        }
        DerivationPathType::Electrum => {
            // Electrum typically uses P2WPKH for newer wallets
            let compressed = bitcoin::CompressedPublicKey(pubkey);
            Address::p2wpkh(&compressed, network)
        }
    };

    Ok(address)
}

/// Scan for addresses matching a target set
/// Returns the first match found
pub fn scan_for_match<F>(
    root: &Xpriv,
    config: &AddressScanConfig,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    mut matcher: F,
) -> Result<Option<DerivedAddress>>
where
    F: FnMut(&Address) -> bool,
{
    let addresses = generate_addresses(root, config, secp)?;

    for derived in addresses {
        if matcher(&derived.address) {
            return Ok(Some(derived));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;

    #[test]
    fn test_derivation_path_types() {
        assert_eq!(DerivationPathType::BIP44.purpose(), 44);
        assert_eq!(DerivationPathType::BIP49.purpose(), 49);
        assert_eq!(DerivationPathType::BIP84.purpose(), 84);
        assert_eq!(DerivationPathType::BIP86.purpose(), 86);
        assert_eq!(DerivationPathType::Electrum.purpose(), 0);
    }

    #[test]
    fn test_path_generation() {
        assert_eq!(
            DerivationPathType::BIP44.path(0),
            "m/44'/0'/0'/0/0"
        );
        assert_eq!(
            DerivationPathType::BIP49.path(5),
            "m/49'/0'/0'/0/5"
        );
        assert_eq!(
            DerivationPathType::BIP84.path(10),
            "m/84'/0'/0'/0/10"
        );
        assert_eq!(
            DerivationPathType::Electrum.path(3),
            "m/0'/0/3"
        );
    }

    #[test]
    fn test_scan_config_total_addresses() {
        let single = AddressScanConfig::single_address(DerivationPathType::BIP44);
        assert_eq!(single.total_addresses(), 1);

        let extended = AddressScanConfig::extended_indices(DerivationPathType::BIP44, 19);
        assert_eq!(extended.total_addresses(), 20); // indices 0-19

        let multi = AddressScanConfig::multi_path();
        assert_eq!(multi.total_addresses(), 3); // BIP44/49/84

        let comprehensive = AddressScanConfig::comprehensive(19);
        assert_eq!(comprehensive.total_addresses(), 60); // 3 paths * 20 indices

        let mut with_change = AddressScanConfig::comprehensive(19);
        with_change.include_change = true;
        assert_eq!(with_change.total_addresses(), 120); // 3 paths * 20 indices * 2 chains
    }

    #[test]
    fn test_generate_addresses() {
        let mnemonic = Mnemonic::parse_in_normalized(
            bip39::Language::English,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();

        let seed = mnemonic.to_seed("");
        let secp = Secp256k1::new();
        let root = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();

        // Single address
        let config = AddressScanConfig::single_address(DerivationPathType::BIP44);
        let addresses = generate_addresses(&root, &config, &secp).unwrap();
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].path, "m/44'/0'/0'/0/0");
        assert_eq!(addresses[0].index, 0);
        assert!(!addresses[0].is_change);

        // Extended indices
        let config = AddressScanConfig::extended_indices(DerivationPathType::BIP84, 4);
        let addresses = generate_addresses(&root, &config, &secp).unwrap();
        assert_eq!(addresses.len(), 5); // indices 0-4
        assert!(addresses.iter().all(|a| a.path_type == DerivationPathType::BIP84));

        // Multi-path
        let config = AddressScanConfig::multi_path();
        let addresses = generate_addresses(&root, &config, &secp).unwrap();
        assert_eq!(addresses.len(), 3); // BIP44, BIP49, BIP84
        assert_eq!(addresses[0].path_type, DerivationPathType::BIP44);
        assert_eq!(addresses[1].path_type, DerivationPathType::BIP49);
        assert_eq!(addresses[2].path_type, DerivationPathType::BIP84);
    }

    #[test]
    fn test_address_formats() {
        let mnemonic = Mnemonic::parse_in_normalized(
            bip39::Language::English,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        ).unwrap();

        let seed = mnemonic.to_seed("");
        let secp = Secp256k1::new();
        let root = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();

        let config = AddressScanConfig::multi_path();
        let addresses = generate_addresses(&root, &config, &secp).unwrap();

        // BIP44 (Legacy) should start with "1"
        assert!(addresses[0].address.to_string().starts_with("1"));

        // BIP49 (Nested SegWit) should start with "3"
        assert!(addresses[1].address.to_string().starts_with("3"));

        // BIP84 (Native SegWit) should start with "bc1q"
        assert!(addresses[2].address.to_string().starts_with("bc1q"));
    }
}
