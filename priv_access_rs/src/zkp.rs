use crate::crypto::{P, G, Q, power_mod};
use num_bigint::BigUint;
use num_traits::Num;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Proof {
    pub public_key: String,
    pub commitment: String,
    pub response: String,
    pub geohash: String, // New: geohash as part of the proof
}

pub struct SchnorrVerifier;

impl SchnorrVerifier {
    /// Verify the ZK Proof.
    /// Proof contains: { "public_key": Y, "commitment": R, "response": s }
    /// Verification Equation: G^s == R * Y^c  (mod P)
    /// Where c = Hash(R, Y)
    pub fn verify_proof(proof: &Proof) -> bool {
        let y = match BigUint::from_str_radix(&proof.public_key, 10) {
            Ok(val) => val,
            Err(_) => return false,
        };
        let r_comm = match BigUint::from_str_radix(&proof.commitment, 10) {
            Ok(val) => val,
            Err(_) => return false,
        };
        let s = match BigUint::from_str_radix(&proof.response, 10) {
            Ok(val) => val,
            Err(_) => return false,
        };

        // 1. Recompute Challenge c = Hash(R, Y, geohash)
        let geohash_prefix = if proof.geohash.len() >= 6 { &proof.geohash[0..6] } else { &proof.geohash };
        println!("TERMINAL: [ZKP] Verifying Identity for geofence: {}", geohash_prefix);
        
        let challenge_input = format!("{}{}{}", r_comm, y, geohash_prefix);
        let mut hasher = Sha256::new();
        hasher.update(challenge_input.as_bytes());
        let result = hasher.finalize();
        let c_hash = BigUint::from_bytes_be(&result);
        let c = c_hash % &*Q;
        println!("TERMINAL: [ZKP] Compute Challenge c = {}", c);

        // 2. Compute LHS: G^s mod P
        let lhs = power_mod(&G, &s, &P);

        // 3. Compute RHS: R * Y^c mod P
        let rhs_part2 = power_mod(&y, &c, &P);
        let rhs = (&r_comm * &rhs_part2) % &*P;

        println!("TERMINAL: [ZKP] Verification EQUATION: LHS={} | RHS={}", lhs, rhs);

        // 4. Check Equality
        let is_valid = lhs == rhs;
        println!("TERMINAL: [ZKP] Verification RESULT: {}", if is_valid { "PASSED" } else { "FAILED" });
        is_valid
    }
}

pub struct SchnorrProver {
    private_key: BigUint,
    public_key: BigUint,
}

impl SchnorrProver {
    pub fn new(private_key: BigUint) -> Self {
        let public_key = power_mod(&G, &private_key, &P);
        SchnorrProver {
            private_key,
            public_key,
        }
    }

    pub fn generate_proof(&self, geohash: String) -> Proof {
        use crate::crypto::Q;
        use num_bigint::{RandBigInt, BigUint};
        use num_traits::One;
        
        // 1. Random nonce r
        let mut rng = rand::thread_rng();
        let limit = &*Q - BigUint::one();
        let start = num_traits::One::one();
        let r = rng.gen_biguint_range(&start, &limit);

        // 2. Commitment R = G^r mod P
        let r_comm = power_mod(&G, &r, &P);

        // 3. Challenge c = Hash(R, Public Key, geohash_prefix)
        let geohash_prefix = if geohash.len() >= 6 { &geohash[0..6] } else { &geohash };
        let challenge_input = format!("{}{}{}", r_comm, self.public_key, geohash_prefix);
        let mut hasher = Sha256::new();
        hasher.update(challenge_input.as_bytes());
        let result = hasher.finalize();
        let c_hash = BigUint::from_bytes_be(&result);
        let c = c_hash % &*Q;

        // 4. Response s = r + c * x mod Q
        let cx = &c * &self.private_key;
        let numerator = &r + &cx;
        let s = numerator % &*Q;

        Proof {
            public_key: self.public_key.to_string(),
            commitment: r_comm.to_string(),
            response: s.to_string(),
            geohash,
        }
    }
}
