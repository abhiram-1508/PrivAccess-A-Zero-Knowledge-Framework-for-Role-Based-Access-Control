use num_bigint::BigUint;
use num_traits::{Num, One};
use once_cell::sync::Lazy;

// NIST 2048-bit Prime (or smaller safe prime from Python code)
// We use the same hex strings as in the Python code for compatibility.
// WARNING: This 1024-bit prime is for educational/demo safety. Use 2048+ or ECC for production.
const PRIME_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
const GENERATOR_HEX: &str = "02";

pub static P: Lazy<BigUint> = Lazy::new(|| BigUint::from_str_radix(PRIME_HEX, 16).unwrap());
pub static G: Lazy<BigUint> = Lazy::new(|| BigUint::from_str_radix(GENERATOR_HEX, 16).unwrap());
pub static Q: Lazy<BigUint> = Lazy::new(|| (&*P - BigUint::one()) / 2u32);

pub fn get_random_secret() -> BigUint {
    let mut rng = rand::thread_rng();
    // Generate a random BigUint below Q (simplified, actual distribution might need more care for security)
    // num-bigint's rand integration:
    use num_bigint::RandBigInt;
    let limit = &*Q - BigUint::one();
    rng.gen_biguint_range(&BigUint::one(), &limit)
}

pub fn power_mod(base: &BigUint, exp: &BigUint, mod_val: &BigUint) -> BigUint {
    base.modpow(exp, mod_val)
}

pub fn str_to_int(s: &str) -> BigUint {
    BigUint::from_bytes_be(s.as_bytes())
}
