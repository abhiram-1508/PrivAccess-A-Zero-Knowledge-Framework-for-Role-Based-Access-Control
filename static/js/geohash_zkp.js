// Geohash ZKP Browser Flow
// Requires: ngeohash, snarkjs (WASM build), geohash_prefix.wasm, geohash_prefix.zkey

// 1. Load dependencies (assume snarkjs and ngeohash are loaded via <script> tags)
// <script src="https://cdn.jsdelivr.net/npm/ngeohash@0.6.3/build/ngeohash.min.js"></script>
// <script src="/static/js/snarkjs.min.js"></script>

async function runGeohashZKP(allowedPrefixStr = 't1q7hk') {
  // 2. Get geolocation
  navigator.geolocation.getCurrentPosition(async (pos) => {
    const lat = pos.coords.latitude;
    const lon = pos.coords.longitude;
    // 3. Encode to geohash (7 chars)
    const geohash = ngeohash.encode(lat, lon, 7); // e.g., 't1q7hkf'
    const userHash = geohash.split('').map(c => c.charCodeAt(0));
    const allowedPrefix = allowedPrefixStr.split('').map(c => c.charCodeAt(0));

    // 4. Prepare input for circuit
    const input = { userHash, allowedPrefix };

    // 5. Load WASM and zkey
    const {witnessCalculator} = await window.snarkjs.wtns.calculate(input, '/static/zkp/geohash_prefix.wasm');
    const wtns = await witnessCalculator.calculateWTNSBin(input, 0);

    // 6. Prove
    const {proof, publicSignals} = await window.snarkjs.groth16.prove(
      '/static/zkp/geohash_prefix.zkey',
      wtns
    );

    // 7. Submit to backend
    const res = await fetch('/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ proof, publicSignals })
    });
    const data = await res.text();
    alert(data);
  }, (err) => {
    alert('Geolocation error: ' + err.message);
  });
}

// Usage: call runGeohashZKP() on a button click or page load
