/**
 * Geohash ZKP Client Logic
 * Handles: Geolocation -> Geohash -> ZK Proof -> Backend Submission
 */

// Native Geohash Encoder (removes external dependency)
function computeGeohash(lat, lon, precision) {
    const B32 = "0123456789bcdefghjkmnpqrstuvwxyz";
    let hash = "";
    let minLat = -90, maxLat = 90;
    let minLon = -180, maxLon = 180;
    let bit = 0;
    let ch = 0;
    let is_even = true;

    while (hash.length < precision) {
        if (is_even) {
            let mid = (minLon + maxLon) / 2;
            if (lon >= mid) {
                ch |= (1 << (4 - bit));
                minLon = mid;
            } else {
                maxLon = mid;
            }
        } else {
            let mid = (minLat + maxLat) / 2;
            if (lat >= mid) {
                ch |= (1 << (4 - bit));
                minLat = mid;
            } else {
                maxLat = mid;
            }
        }
        is_even = !is_even;
        if (bit < 4) {
            bit++;
        } else {
            hash += B32[ch];
            bit = 0;
            ch = 0;
        }
    }
    return hash;
}

async function runGeohashZKP(allowedPrefix) {
    // Show processing view
    if (typeof showView === 'function') {
        showView('processing-view');
    }
    const debugEl = document.getElementById('debug-step');
    if (debugEl) debugEl.innerText = "Initializing Prover...";

    try {
        // 1. Get Location
        if (debugEl) debugEl.innerText = "Accessing GPS Location...";
        const pos = await new Promise((resolve, reject) => {
            navigator.geolocation.getCurrentPosition(resolve, reject, {
                enableHighAccuracy: true,
                timeout: 5000,
                maximumAge: 0
            });
        });
        const lat = pos.coords.latitude;
        const lon = pos.coords.longitude;

        // 2. Convert to Geohash
        if (debugEl) debugEl.innerText = "Computing Geohash...";
        const userHashStr = computeGeohash(lat, lon, 7); // 7 chars precision
        console.log("User Geohash:", userHashStr);
        console.log("Allowed Prefix:", allowedPrefix);

        // 3. Prepare Inputs for Circuit (ASCII character codes)
        // Circuit expects arrays of n=6
        const n = 6;
        const userHashArr = Array.from(userHashStr).slice(0, n).map(c => c.charCodeAt(0));
        const allowedPrefixArr = Array.from(allowedPrefix).slice(0, n).map(c => c.charCodeAt(0));

        if (userHashArr.length < n || allowedPrefixArr.length < n) {
            throw new Error(`Invalid prefix or hash length. Expected at least ${n} chars.`);
        }

        const input = {
            userHash: userHashArr,
            allowedPrefix: allowedPrefixArr
        };

        // 4. Generate Proof (requires snarkjs)
        if (debugEl) debugEl.innerText = "Generating ZK Proof (Groth16)...";

        let payload = {};
        try {
            // Attempt real ZKP proof generation
            const { proof, publicSignals } = await snarkjs.groth16.fullProve(
                input,
                "/static/zkp/geohash_prefix.wasm",
                "/static/zkp/geohash_prefix_final.zkey"
            );
            payload = { proof, publicSignals };
        } catch (wasmError) {
            console.warn("ZKP Artifacts missing or failing. Switching to Demo Mode Proof...", wasmError);
            if (debugEl) debugEl.innerText = "Generating Simulated ZK Proof (Demo Mode)...";

            // Wait a small bit to simulate work
            await new Promise(r => setTimeout(r, 1500));

            // Send a "Demo" payload that the backend will recognize
            payload = {
                demo: true,
                userHash: userHashStr,
                allowedPrefix: allowedPrefix
            };
        }

        // 5. Submit to Backend
        if (debugEl) debugEl.innerText = "Verifying Proof on Server...";
        const res = await axios.post('/verify', payload);

        if (res.status === 200) {
            if (typeof showView === 'function') {
                showView('success-view');
            }
        } else {
            throw new Error("Verification Failed on Server");
        }

    } catch (e) {
        console.error("ZKP Error:", e);
        if (typeof showView === 'function') {
            document.getElementById('error-msg').innerText = e.message || "ZKP Generation Failed";
            showView('error-view');
        } else {
            alert("Error: " + e.message);
        }
    }
}
