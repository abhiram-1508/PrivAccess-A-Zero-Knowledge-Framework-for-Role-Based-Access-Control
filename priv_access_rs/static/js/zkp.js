/*
    Client-side Schnorr Prover
    Note: Python uses large integers by default. JS needs BigInt.
*/

// Configuration must match server (safe prime from crypto/utils.py)
// Using strings for BigInt constructor
const P_HEX = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
const P = BigInt("0x" + P_HEX);
const G = 2n;
const Q = (P - 1n) / 2n;

// Modular Exponentiation: (base^exp) % mod
function powerMod(base, exp, mod) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) result = (result * base) % mod;
        exp = exp / 2n;
        base = (base * base) % mod;
    }
    return result;
}

// 2. Pure JS SHA-256 Implementation (for HTTP compatibility)
// Source: Minimal SHA-256 implementation for browsers without Secure Context
function sha256_sync(ascii) {
    function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    }

    var mathPow = Math.pow;
    var maxWord = mathPow(2, 32);
    var result = ''

    var words = [];
    var asciiBitLength = ascii.length * 8;

    //* caching results is optional - remove/add slash from front of this line to toggle
    //0x80000000 = 2^31
    var hash = sha256_sync.h = sha256_sync.h || [];
    // new hash as 1st element
    var k = sha256_sync.k = sha256_sync.k || [];
    var primeCounter = k.length;
    /*/
    var hash = [], k = [];
    var primeCounter = 0;
    //*/

    var isComposite = {};
    for (var candidate = 2; primeCounter < 64; candidate++) {
        if (!isComposite[candidate]) {
            for (i = 0; i < 313; i += candidate) {
                isComposite[i] = candidate;
            }
            hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
            k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
        }
    }

    ascii += '\x80' // Append Ƈ' bit (plus zero padding)
    while (ascii.length % 64 - 56) ascii += '\x00' // More zero padding
    for (var i = 0; i < ascii.length; i++) {
        var j = ascii.charCodeAt(i);
        if (j >> 8) return; // ASCII check: only accept characters in range 0-255
        words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words.length] = ((asciiBitLength / maxWord) | 0);
    words[words.length] = (asciiBitLength)

    for (var j = 0; j < words.length;) {
        var w = words.slice(j, j += 16);
        var oldHash = hash;
        // This is now the "working hash", often labelled as variables a..h
        // (we have to copy the array because we don't want to modify the original)
        hash = hash.slice(0, 8);

        for (var i = 0; i < 64; i++) {
            var i2 = i + j;
            // Expand the message schedule if needed
            var w15 = w[i - 15], w2 = w[i - 2];

            // Iterate
            var a = hash[0], e = hash[4];
            var temp1 = hash[7]
                + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) // S1
                + ((e & hash[5]) ^ ((~e) & hash[6])) // ch
                + k[i]
                // Expand the message schedule if needed
                + (w[i] = (i < 16) ? w[i] : (
                    w[i - 16]
                    + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) // s0
                    + w[i - 7]
                    + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10)) // s1
                ) | 0
                );
            // This is only used once, so *could* be moved below, but it only saves 4 bytes and makes things unreadble
            var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) // S0
                + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2])); // maj

            hash = [(temp1 + temp2) | 0].concat(hash); // We don't save the old 'h' value
            hash[4] = (hash[4] + temp1) | 0;
        }

        for (var i = 0; i < 8; i++) {
            hash[i] = (hash[i] + oldHash[i]) | 0;
        }
    }

    for (var i = 0; i < 8; i++) {
        for (var j = 3; j + 1; j--) {
            var b = (hash[i] >> (j * 8)) & 255;
            result += ((b < 16) ? 0 : '') + b.toString(16);
        }
    }
    return result;
}

// Wrapper to match previous async signature and return BigInt
async function sha256(message) {
    const hex = sha256_sync(message);
    return BigInt("0x" + hex);
}

class SchnorrProverJS {
    constructor(privateKeyStr) {
        this.privateKey = BigInt(privateKeyStr);
        this.publicKey = powerMod(G, this.privateKey, P);
    }

    async generateProof(geohash) {
        // 1. Random nonce r
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        let hex = "0x" + Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
        let r = BigInt(hex) % (Q - 1n) + 1n;

        // 2. Commitment R = G^r mod P
        let R = powerMod(G, r, P);

        // 3. Challenge c = Hash(R, Public Key, geohash_prefix)
        const geohashPrefix = geohash.substring(0, 6);
        let challengeInput = R.toString() + this.publicKey.toString() + geohashPrefix;
        let cBig = await sha256(challengeInput);
        let c = cBig % Q;

        // 4. Response s = r + c * x mod Q
        let s = (r + c * this.privateKey) % Q;

        return {
            "public_key": this.publicKey.toString(),
            "commitment": R.toString(),
            "response": s.toString(),
            "geohash": geohash
        };
    }
}
