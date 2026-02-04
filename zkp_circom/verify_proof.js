const snarkjs = require("snarkjs");
const fs = require("fs");

async function run() {
    // Expected arguments: proof.json, public.json, verification_key.json
    const proofPath = process.argv[2] || "proof.json";
    const publicSignalsPath = process.argv[3] || "public.json";
    const vKeyPath = process.argv[4] || "verification_key.json";

    if (!fs.existsSync(proofPath) || !fs.existsSync(publicSignalsPath) || !fs.existsSync(vKeyPath)) {
        console.error("Missing input files for verification");
        process.exit(1);
    }

    try {
        const proof = JSON.parse(fs.readFileSync(proofPath));
        const publicSignals = JSON.parse(fs.readFileSync(publicSignalsPath));
        const vKey = JSON.parse(fs.readFileSync(vKeyPath));

        const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);

        if (res === true) {
            console.log("Verification OK");
            process.exit(0);
        } else {
            console.log("Invalid proof");
            process.exit(1);
        }
    } catch (err) {
        console.error("Error during verification:", err.message);
        process.exit(1);
    }
}

run().catch(err => {
    console.error(err);
    process.exit(1);
});
