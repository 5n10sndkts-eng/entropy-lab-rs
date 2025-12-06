use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// Generates a 64-byte seed from a mnemonic using Electrum's algorithm.
/// 
/// Electrum uses PBKDF2-HMAC-SHA512 with:
/// - Password: The mnemonic string (normalized NFKD, but we assume ASCII for standard wordlists)
/// - Salt: "electrum" (for standard types)
/// - Rounds: 2048
/// - Output: 64 bytes
pub fn mnemonic_to_seed(mnemonic: &str) -> [u8; 64] {
    let mut seed = [0u8; 64];
    // pbkdf2 handles the iteration logic
    pbkdf2::<HmacSha512>(
        mnemonic.as_bytes(),
        b"electrum",
        2048,
        &mut seed,
    ).expect("PBKDF2 calculation should never fail with valid parameters");
    seed
}
