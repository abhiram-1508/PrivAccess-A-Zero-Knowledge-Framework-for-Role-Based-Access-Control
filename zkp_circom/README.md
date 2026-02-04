# Geohash Prefix ZKP (circom + snarkjs)

## Circuit
- `geohash_prefix.circom`: Checks if user's geohash prefix matches allowed prefix (privacy-preserving geofence).

## Usage

1. **Compile circuit**

```bash
circom geohash_prefix.circom --r1cs --wasm --sym
```

2. **Trusted setup**

```bash
snarkjs groth16 setup geohash_prefix.r1cs pot12_final.ptau geohash_prefix.zkey
snarkjs zkey export verificationkey geohash_prefix.zkey verification_key.json
```

3. **Generate proof**

```bash
node generate_proof.js
```

4. **Verify proof**

```bash
snarkjs groth16 verify verification_key.json public.json proof.json
```

- Edit `generate_proof.js` to set the correct geohash and prefix arrays.
- Use the output `proof.json` and `public.json` in your backend for access control.
