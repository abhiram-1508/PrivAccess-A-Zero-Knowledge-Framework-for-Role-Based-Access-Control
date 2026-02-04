const snarkjs = require('snarkjs');
const fs = require('fs');

// Example input: update with real values in production
const input = {
  userHash: [116,49,113,55,104,107,102],      // User geohash as ASCII codes (e.g., 't1q7hkf')
  allowedPrefix: [116,49,113,55,104,107],     // Allowed prefix as ASCII codes (e.g., 't1q7hk')
};

async function main() {
  // 1. Generate witness
  const {wtns} = await snarkjs.wtns.calculate(
    input,
    './geohash_prefix_js/geohash_prefix.wasm'
  );
  fs.writeFileSync('witness.wtns', wtns);

  // 2. Generate proof
  const {proof, publicSignals} = await snarkjs.groth16.prove(
    './geohash_prefix.zkey',
    wtns
  );
  fs.writeFileSync('proof.json', JSON.stringify(proof, null, 2));
  fs.writeFileSync('public.json', JSON.stringify(publicSignals, null, 2));

  console.log('Proof:', proof);
  console.log('Public Signals:', publicSignals);
}

main().catch(console.error);
