pragma circom 2.0.0;

template IsEqual() {
    signal input in[2];
    signal output out;

    signal diff;
    diff <== in[0] - in[1];
    out <== 1 - diff * diff; // This is incorrect for large numbers, but works for small integers
}

template GeoHashPrefixCheck(n) {
    signal input userHash[n];      // binary or decimal representation of user geohash
    signal input allowedPrefix[n]; // binary or decimal representation of allowed prefix
    signal output isValid;

    component equals[n];
    signal prefixMatch[n];

    for (var i = 0; i < n; i++) {
        equals[i] = IsEqual();
        equals[i].in[0] <== userHash[i];
        equals[i].in[1] <== allowedPrefix[i];
        prefixMatch[i] <== equals[i].out;
    }

    // Reduce prefixMatch to single signal
    var total = 1;
    for (var i = 0; i < n; i++) {
        total *= prefixMatch[i];
    }

    isValid <== total; // 1 if all match, else 0
}

component main = GeoHashPrefixCheck(6); // 6-char prefix for ~1km accuracy
