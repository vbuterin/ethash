BI = Bitcoin.BigInteger;

params = {
      "dag_bytes": 1073741824,
      "cache_bytes": 33554432,       
      "k": 64,
      "cache_rounds": 2,
      "mix_bytes": 4096,
      "accesses": 64,          
      "hash": sha3_512, // Hash function must output a byte array and accept a string or byte array
      "hash_bytes": 64,
      "P": BI("115792089237316195423570985008687907853269984665640564039457584007913129603823"),
}

function modBytes(bytes, m) {
    var o = 0;
    for (var i = 0; i < bytes.length; i++) {
        o = (o * 256 + bytes[i]) % m;
    }
    return o;
}

function genCache(params, seed) {
    var x = new Date().getTime()
    cache = [];
    var h = params.hash(seed);
    var n = params.cache_bytes / params.hash_bytes;
    // Initialize cache
    for (var i = 0; i < n; i++) {
        cache.push(h);
        h = params.hash(h);
        if (i % 10000 == 0) console.log(i);
    }
    // Do randmemohash passes
    for (var _ = 0; _ < params.cache_rounds; _++) {
        for (var i = 0; i < n; i++) {
            var b = cache[i].slice(params.hash_bytes - 8);
            var v = modBytes(b, params.cache_bytes);
            cache[i] = params.hash(cache[(i-1+n)%n].concat(cache[v]));
            if (i % 10000 == 0) console.log(i);
        }
    }
    // Convert to ints for speed
    var c;
    for (var i = 0; i < n; i++) {
        var o = [];
        c = cache[i];
        for (var j = 0; j < 64; j += 4) {
            o.push((c[j] << 24) + (c[j+1] << 16) + (c[j+2] << 8) + c[j+3]);
        }
        cache[i] = o;
    }
    console.log('Runtime: '+(new Date().getTime() - x));
    return cache;
}

SAFE_PRIME = 4294967296 - 209

function modpow(b, e, m) {
    bits = [];
    while (e > 0) { bits.push(e & 1); e >>= 1; }
    o = 1;
    for (var i = bits.length - 1; i >= 0; i--) {
        L = o & 65535;
        H = Math.floor(o / 65536);
        o = ((L * o) + (((H * o) % m) * 65536)) % m;
        if (bits[i]) {
            L = o & 65535;
            H = Math.floor(o / 65536);
            o = ((L * b) + (((H * b) % m) * 65536)) % m;
        }
    }
    return o;
}

function step_bbs(n) { 
    return modpow(n, 3, SAFE_PRIME) 
}

function quick_bbs(n, p) {
    return modpow(n, modpow(3, p, SAFE_PRIME - 1), SAFE_PRIME)
}

function bbs_clamp(n) {
    if (n < 2) return 2;
    else if (n > SAFE_PRIME - 2) return SAFE_PRIME - 2;
    else return n;
}

function calcDagItem(params, seed, cache, i) {
    var n = params.cache_bytes / params.hash_bytes;
    var rand = quick_bbs(bbs_clamp(modBytes(seed.slice(seed.length - 4), SAFE_PRIME)), i);
    var o = [];
    for (var j = 0; j < params.hash_bytes / 4; j ++) o.push(0);
    for (var i = 0; i < params.k; i++) {
        var c = cache[rand % n];
        for (var j = 0; j < params.hash_bytes / 4; j ++) o[j] ^= c[j];
        rand = step_bbs(rand);
    }
    return o;
}

function hashimoto(params, seed, cache, header, nonce) {
    var x = new Date().getTime()
    var w = params.mix_bytes / params.hash_bytes
    var n = params.dag_bytes / params.hash_bytes
    var o = []
    for (var j = 0; j < params.mix_bytes / 4; j ++) o.push(0);
    var s = params.hash(header + nonce)
    var rand = bbs_clamp(modBytes(s.slice(s.length - 4), SAFE_PRIME))
    for (var _ = 0; _ < params.accesses; _++) {
        var p = rand % (n / w) * w;
        for (var j = 0; j < w; j += 1) {
            var d = calcDagItem(params, seed, cache, p + j);
            for (var k = 0; k < params.hash_bytes / 4; k++) {
                o[params.hash_bytes / 4 * j + k] ^= d[k];
            }
        }
        rand = step_bbs(rand);
    }
    var acc = s
    for (var j = 0; j < o.length; j++) {
        acc.push(o[j] >> 24);
        acc.push((o[j] >> 16) & 255);
        acc.push((o[j] >> 8) & 255);
        acc.push(o[j] & 255);
    }
    console.log('Runtime: '+(new Date().getTime() - x));
    return sha3_256(s.concat(sha3_256(acc)));
}
