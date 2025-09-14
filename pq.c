#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Kyber768 Parameters
#define KYBER_N 256
#define KYBER_K 3
#define KYBER_Q 3329
#define KYBER_ETA1 2
#define KYBER_ETA2 2
#define KYBER_POLYBYTES 384
#define KYBER_POLYVECBYTES (KYBER_K * KYBER_POLYBYTES)
#define KYBER_PUBLICKEYBYTES (KYBER_POLYVECBYTES + 32)
#define KYBER_SECRETKEYBYTES (KYBER_POLYVECBYTES + KYBER_PUBLICKEYBYTES + 32 + 32)
#define KYBER_CIPHERTEXTBYTES (KYBER_POLYVECBYTES + KYBER_POLYBYTES)
#define KYBER_SSBYTES 32

// Function prototypes
void secure_randombytes(uint8_t *x, size_t xlen);
void kyber_keypair(uint8_t *pk, uint8_t *sk);
void kyber_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
void kyber_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
void poly_getnoise_eta1(int16_t *r, const uint8_t *seed, uint8_t nonce);
void poly_getnoise_eta2(int16_t *r, const uint8_t *seed, uint8_t nonce);
void poly_ntt(int16_t *r);
void poly_invntt(int16_t *r);
void poly_basemul(int16_t *r, const int16_t *a, const int16_t *b);
void poly_frommsg(int16_t *r, const uint8_t *msg);
void poly_tomsg(uint8_t *msg, const int16_t *r);
void poly_add(int16_t *r, const int16_t *a, const int16_t *b);
void poly_sub(int16_t *r, const int16_t *a, const int16_t *b);
void polyvec_ntt(int16_t r[KYBER_K][KYBER_N]);
void polyvec_invntt(int16_t r[KYBER_K][KYBER_N]);
void polyvec_basemul(int16_t r[KYBER_K][KYBER_N], const int16_t a[KYBER_K][KYBER_N], 
                     const int16_t b[KYBER_K][KYBER_N]);
void polyvec_add(int16_t r[KYBER_K][KYBER_N], const int16_t a[KYBER_K][KYBER_N], 
                 const int16_t b[KYBER_K][KYBER_N]);
void polyvec_sub(int16_t r[KYBER_K][KYBER_N], const int16_t a[KYBER_K][KYBER_N], 
                 const int16_t b[KYBER_K][KYBER_N]);
void polyvec_compress(uint8_t *r, const int16_t a[KYBER_K][KYBER_N]);
void polyvec_decompress(int16_t r[KYBER_K][KYBER_N], const uint8_t *a);
void poly_compress(uint8_t *r, const int16_t *a);
void poly_decompress(int16_t *r, const uint8_t *a);
void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);
void sha3_512(uint8_t *output, const uint8_t *input, size_t inlen);
void shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);
void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);
void poly_frombytes(int16_t *r, const uint8_t *a);
void poly_tobytes(uint8_t *r, const int16_t *a);
void print_poly(const char *label, const int16_t *p);
void print_polyvec(const char *label, const int16_t p[KYBER_K][KYBER_N]);

// Cryptographically secure random number generator
void secure_randombytes(uint8_t *x, size_t xlen) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        fprintf(stderr, "Error: Could not open /dev/urandom\n");
        exit(1);
    }
    if (fread(x, 1, xlen, f) != xlen) {
        fprintf(stderr, "Error: Could not read from /dev/urandom\n");
        fclose(f);
        exit(1);
    }
    fclose(f);
}

// Simplified SHA3 implementation (Keccak) for demonstration
void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen) {
    // Simplified implementation
    for (size_t i = 0; i < 32; i++) {
        output[i] = 0;
        for (size_t j = 0; j < inlen; j++) {
            output[i] ^= input[j] + i + j;
        }
    }
}

void sha3_512(uint8_t *output, const uint8_t *input, size_t inlen) {
    // Simplified implementation
    for (size_t i = 0; i < 64; i++) {
        output[i] = 0;
        for (size_t j = 0; j < inlen; j++) {
            output[i] ^= input[j] + i + j;
        }
    }
}

void shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen) {
    // Simplified implementation
    for (size_t i = 0; i < outlen; i++) {
        output[i] = 0;
        for (size_t j = 0; j < inlen; j++) {
            output[i] ^= input[j] + i + j;
        }
    }
}

void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen) {
    // Simplified implementation
    for (size_t i = 0; i < outlen; i++) {
        output[i] = 0;
        for (size_t j = 0; j < inlen; j++) {
            output[i] ^= input[j] + i + j + 0x100;
        }
    }
}

// Zeta array for NTT
static const int16_t zetas[128] = {
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962, 2127, 1855, 1468,
    573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017, 732, 608, 1787, 411, 3124, 1758,
    1223, 652, 2777, 1015, 2036, 1491, 3047, 1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469,
    2476, 3239, 3058, 830, 107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054,
    2226, 430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574, 1653, 3083,
    778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173, 3254, 817,
    1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193, 1218, 1994, 2455, 220, 2142, 1670, 2144,
    1799, 2051, 794, 1819, 2475, 2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628
};

// Montgomery reduction
static int16_t montgomery_reduce(int32_t a) {
    int32_t t;
    int16_t u;

    u = a * 62209;
    t = (int32_t)u * KYBER_Q;
    t = a - t;
    t >>= 16;
    return t;
}

// Barrett reduction
static int16_t barrett_reduce(int16_t a) {
    int16_t t;
    const int16_t v = ((1U << 26) + KYBER_Q / 2) / KYBER_Q;

    t = (int32_t)v * a >> 26;
    t = t * KYBER_Q;
    return a - t;
}

// Conditional subtraction of Q
static int16_t csubq(int16_t a) {
    a -= KYBER_Q;
    a += (a >> 15) & KYBER_Q;
    return a;
}

// Convert bytes to polynomial
void poly_frombytes(int16_t *r, const uint8_t *a) {
    for (size_t i = 0; i < KYBER_N / 2; i++) {
        r[2*i]   = a[3*i]       | ((a[3*i+1] & 0x0f) << 8);
        r[2*i+1] = (a[3*i+1] >> 4) | (a[3*i+2] << 4);
        r[2*i]   = csubq(r[2*i]);
        r[2*i+1] = csubq(r[2*i+1]);
    }
}

// Convert polynomial to bytes
void poly_tobytes(uint8_t *r, const int16_t *a) {
    int16_t t[2];
    
    for (size_t i = 0; i < KYBER_N / 2; i++) {
        t[0] = csubq(a[2*i]);
        t[1] = csubq(a[2*i+1]);
        
        r[3*i]     = t[0] & 0xff;
        r[3*i+1]   = (t[0] >> 8) | (t[1] & 0x0f) << 4;
        r[3*i+2]   = t[1] >> 4;
    }
}

// Generate noise polynomial using centered binomial distribution
void poly_getnoise_eta1(int16_t *r, const uint8_t *seed, uint8_t nonce) {
    uint8_t buf[KYBER_ETA1 * KYBER_N / 4];
    uint8_t extseed[32 + 1];
    
    memcpy(extseed, seed, 32);
    extseed[32] = nonce;
    
    // Use SHAKE-128 to generate noise
    shake128(buf, sizeof(buf), extseed, 33);
    
    for (size_t i = 0; i < KYBER_N; i++) {
        uint16_t t = buf[i] | (buf[i + KYBER_N/2] << 8);
        uint16_t d = 0;
        for (size_t j = 0; j < 8; j++) {
            d += (t >> j) & 0x0101;
        }
        r[i] = (d & 0xff) - (d >> 8);
        r[i] = csubq(r[i]);
    }
}

void poly_getnoise_eta2(int16_t *r, const uint8_t *seed, uint8_t nonce) {
    uint8_t buf[KYBER_ETA2 * KYBER_N / 4];
    uint8_t extseed[32 + 1];
    
    memcpy(extseed, seed, 32);
    extseed[32] = nonce;
    
    // Use SHAKE-128 to generate noise
    shake128(buf, sizeof(buf), extseed, 33);
    
    for (size_t i = 0; i < KYBER_N; i++) {
        uint16_t t = buf[i] | (buf[i + KYBER_N/2] << 8);
        uint16_t d = 0;
        for (size_t j = 0; j < 4; j++) {
            d += (t >> j) & 0x0303;
        }
        r[i] = (d & 0xff) - (d >> 8);
        r[i] = csubq(r[i]);
    }
}

// Forward NTT transform
void poly_ntt(int16_t *r) {
    int len, start, j, k;
    int16_t t, zeta;

    k = 0;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = zetas[k++];
            for (j = start; j < start + len; j++) {
                t = montgomery_reduce(zeta * r[j + len]);
                r[j + len] = barrett_reduce(r[j] - t);
                r[j] = barrett_reduce(r[j] + t);
            }
        }
    }
}

// Inverse NTT transform
void poly_invntt(int16_t *r) {
    int len, start, j, k;
    int16_t t, zeta;

    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < 256; start = j + len) {
            zeta = zetas[k--];
            for (j = start; j < start + len; j++) {
                t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = barrett_reduce(t - r[j + len]);
                r[j + len] = montgomery_reduce(zeta * r[j + len]);
            }
        }
    }

    // Final normalization
    int16_t f = 1441; // 1441 = 128^{-1} mod 3329
    for (size_t i = 0; i < KYBER_N; i++) {
        r[i] = montgomery_reduce(f * r[i]);
    }
}

// Polynomial multiplication
void poly_basemul(int16_t *r, const int16_t *a, const int16_t *b) {
    for (size_t i = 0; i < KYBER_N / 4; i++) {
        int16_t t0, t1, t2, t3;
        
        t0 = montgomery_reduce(a[4*i] * b[4*i]);
        t1 = montgomery_reduce(a[4*i+1] * b[4*i+1]);
        t2 = montgomery_reduce(a[4*i+2] * b[4*i+2]);
        t3 = montgomery_reduce(a[4*i+3] * b[4*i+3]);
        
        r[4*i] = barrett_reduce(t0 + t1);
        r[4*i+1] = barrett_reduce(t2 + t3);
        r[4*i+2] = barrett_reduce(t0 - t1);
        r[4*i+3] = barrett_reduce(t2 - t3);
    }
}

// Convert message to polynomial
void poly_frommsg(int16_t *r, const uint8_t *msg) {
    for (size_t i = 0; i < KYBER_N / 8; i++) {
        for (size_t j = 0; j < 8; j++) {
            r[8*i+j] = ((msg[i] >> j) & 1) * ((KYBER_Q + 1) / 2);
        }
    }
}

// Convert polynomial to message
void poly_tomsg(uint8_t *msg, const int16_t *r) {
    uint16_t t;
    
    for (size_t i = 0; i < KYBER_N / 8; i++) {
        msg[i] = 0;
        for (size_t j = 0; j < 8; j++) {
            t = r[8*i+j];
            t += (t >> 15) & KYBER_Q;
            t = (t * 2) / KYBER_Q;
            msg[i] |= (t & 1) << j;
        }
    }
}

// Polynomial addition
void poly_add(int16_t *r, const int16_t *a, const int16_t *b) {
    for (size_t i = 0; i < KYBER_N; i++) {
        r[i] = barrett_reduce(a[i] + b[i]);
    }
}

// Polynomial subtraction
void poly_sub(int16_t *r, const int16_t *a, const int16_t *b) {
    for (size_t i = 0; i < KYBER_N; i++) {
        r[i] = barrett_reduce(a[i] - b[i]);
    }
}

// Vector NTT transform
void polyvec_ntt(int16_t r[KYBER_K][KYBER_N]) {
    for (size_t i = 0; i < KYBER_K; i++) {
        poly_ntt(r[i]);
    }
}

// Vector inverse NTT transform
void polyvec_invntt(int16_t r[KYBER_K][KYBER_N]) {
    for (size_t i = 0; i < KYBER_K; i++) {
        poly_invntt(r[i]);
    }
}

// Vector multiplication
void polyvec_basemul(int16_t r[KYBER_K][KYBER_N], const int16_t a[KYBER_K][KYBER_N], 
                     const int16_t b[KYBER_K][KYBER_N]) {
    for (size_t i = 0; i < KYBER_K; i++) {
        poly_basemul(r[i], a[i], b[i]);
    }
}

// Vector addition
void polyvec_add(int16_t r[KYBER_K][KYBER_N], const int16_t a[KYBER_K][KYBER_N], 
                 const int16_t b[KYBER_K][KYBER_N]) {
    for (size_t i = 0; i < KYBER_K; i++) {
        poly_add(r[i], a[i], b[i]);
    }
}

// Vector subtraction
void polyvec_sub(int16_t r[KYBER_K][KYBER_N], const int16_t a[KYBER_K][KYBER_N], 
                 const int16_t b[KYBER_K][KYBER_N]) {
    for (size_t i = 0; i < KYBER_K; i++) {
        poly_sub(r[i], a[i], b[i]);
    }
}

// Compress polynomial vector
void polyvec_compress(uint8_t *r, const int16_t a[KYBER_K][KYBER_N]) {
    size_t i, j, k;
    uint16_t t[4];
    
    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_N / 4; j++) {
            for (k = 0; k < 4; k++) {
                t[k] = a[i][4*j+k];
                t[k] += (t[k] >> 15) & KYBER_Q;
                t[k] = (((t[k] << 10) + KYBER_Q/2) / KYBER_Q) & 0x3ff;
            }
            
            r[0] = t[0] >> 0;
            r[1] = (t[0] >> 8) | (t[1] << 2);
            r[2] = (t[1] >> 6) | (t[2] << 4);
            r[3] = (t[2] >> 4) | (t[3] << 6);
            r[4] = t[3] >> 2;
            r += 5;
        }
    }
}

// Decompress polynomial vector
void polyvec_decompress(int16_t r[KYBER_K][KYBER_N], const uint8_t *a) {
    size_t i, j;
    
    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_N / 4; j++) {
            r[i][4*j+0] = ((a[0] >> 0) | (a[1] << 8)) & 0x3ff;
            r[i][4*j+1] = ((a[1] >> 2) | (a[2] << 6)) & 0x3ff;
            r[i][4*j+2] = ((a[2] >> 4) | (a[3] << 4)) & 0x3ff;
            r[i][4*j+3] = ((a[3] >> 6) | (a[4] << 2)) & 0x3ff;
            a += 5;
            
            for (size_t k = 0; k < 4; k++) {
                r[i][4*j+k] = (r[i][4*j+k] * KYBER_Q + 512) >> 10;
            }
        }
    }
}

// Compress polynomial
void poly_compress(uint8_t *r, const int16_t *a) {
    uint16_t t[8];
    size_t i, j;
    
    for (i = 0; i < KYBER_N; i += 8) {
        for (j = 0; j < 8; j++) {
            t[j] = a[i+j];
            t[j] += (t[j] >> 15) & KYBER_Q;
            t[j] = (((t[j] << 3) + KYBER_Q/2) / KYBER_Q) & 0x7;
        }
        
        r[0] = t[0] | (t[1] << 3) | (t[2] << 6);
        r[1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
        r[2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
        r += 3;
    }
}

// Decompress polynomial
void poly_decompress(int16_t *r, const uint8_t *a) {
    size_t i;
    
    for (i = 0; i < KYBER_N; i += 8) {
        r[i+0] = (a[0] >> 0) & 7;
        r[i+1] = (a[0] >> 3) & 7;
        r[i+2] = (a[0] >> 6) | ((a[1] << 2) & 4);
        r[i+3] = (a[1] >> 1) & 7;
        r[i+4] = (a[1] >> 4) & 7;
        r[i+5] = (a[1] >> 7) | ((a[2] << 1) & 6);
        r[i+6] = (a[2] >> 2) & 7;
        r[i+7] = (a[2] >> 5) & 7;
        a += 3;
        
        for (size_t j = 0; j < 8; j++) {
            r[i+j] = (r[i+j] * KYBER_Q + 4) >> 3;
        }
    }
}

// Debugging functions
void print_poly(const char *label, const int16_t *p) {
    printf("%s: [", label);
    for (int i = 0; i < 10; i++) {
        printf("%d, ", p[i]);
    }
    printf("...]\n");
}

void print_polyvec(const char *label, const int16_t p[KYBER_K][KYBER_N]) {
    printf("%s:\n", label);
    for (int i = 0; i < KYBER_K; i++) {
        printf("  [%d]: [", i);
        for (int j = 0; j < 10; j++) {
            printf("%d, ", p[i][j]);
        }
        printf("...]\n");
    }
}

// Key generation
void kyber_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t buf[64];
    uint8_t publicseed[32], noiseseed[32];
    int16_t a[KYBER_K][KYBER_K][KYBER_N];
    int16_t s[KYBER_K][KYBER_N], e[KYBER_K][KYBER_N];
    int16_t t[KYBER_K][KYBER_N];
    
    // Generate random seeds
    secure_randombytes(buf, 64);
    
    // Expand public seed and noise seed using SHAKE-256
    shake256(publicseed, 32, buf, 32);
    shake256(noiseseed, 32, buf + 32, 32);
    
    // Generate matrix A using SHAKE-128
    for (size_t i = 0; i < KYBER_K; i++) {
        for (size_t j = 0; j < KYBER_K; j++) {
            uint8_t seed[33];
            memcpy(seed, publicseed, 32);
            seed[32] = i + j * KYBER_K;
            
            uint8_t buf[384];
            shake128(buf, sizeof(buf), seed, 33);
            
            // Convert bytes to polynomial in the range [0, Q-1]
            for (size_t k = 0; k < KYBER_N; k++) {
                a[i][j][k] = (buf[k] | (buf[k + 128] << 8)) % KYBER_Q;
            }
        }
    }
    
    // Generate secret vector s
    for (size_t i = 0; i < KYBER_K; i++) {
        poly_getnoise_eta1(s[i], noiseseed, i);
    }
    
    // Generate error vector e
    for (size_t i = 0; i < KYBER_K; i++) {
        poly_getnoise_eta1(e[i], noiseseed, i + KYBER_K);
    }
    
    // Compute t = A*s + e
    for (size_t i = 0; i < KYBER_K; i++) {
        for (size_t j = 0; j < KYBER_N; j++) {
            t[i][j] = e[i][j];
            for (size_t k = 0; k < KYBER_K; k++) {
                // Simple polynomial multiplication (for debugging)
                for (size_t l = 0; l < KYBER_N; l++) {
                    if (j >= l) {
                        t[i][j] = (t[i][j] + a[i][k][l] * s[k][j-l]) % KYBER_Q;
                    } else {
                        t[i][j] = (t[i][j] - a[i][k][l] * s[k][j + KYBER_N - l]) % KYBER_Q;
                    }
                }
            }
            t[i][j] = csubq(t[i][j]);
        }
    }
    
    // Pack public key
    polyvec_compress(pk, t);
    memcpy(pk + KYBER_POLYVECBYTES, publicseed, 32);
    
    // Pack secret key
    polyvec_compress(sk, s);
    memcpy(sk + KYBER_POLYVECBYTES, pk, KYBER_PUBLICKEYBYTES);
    memcpy(sk + KYBER_POLYVECBYTES + KYBER_PUBLICKEYBYTES, noiseseed, 32);
    
    // Clean up sensitive data
    memset(buf, 0, sizeof(buf));
    memset(s, 0, sizeof(s));
    memset(e, 0, sizeof(e));
}

// Encapsulation
void kyber_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    uint8_t buf[32];
    uint8_t publicseed[32];
    int16_t sp[KYBER_K][KYBER_N], ep[KYBER_K][KYBER_N], epp[KYBER_N];
    int16_t pkpv[KYBER_K][KYBER_N], at[KYBER_K][KYBER_K][KYBER_N];
    int16_t bp[KYBER_K][KYBER_N], v[KYBER_N], mp[KYBER_N];
    
    // Unpack public key
    polyvec_decompress(pkpv, pk);
    memcpy(publicseed, pk + KYBER_POLYVECBYTES, 32);
    
    // Generate random message
    secure_randombytes(buf, 32);
    
    // Generate matrix A^T using SHAKE-128
    for (size_t i = 0; i < KYBER_K; i++) {
        for (size_t j = 0; j < KYBER_K; j++) {
            uint8_t seed[33];
            memcpy(seed, publicseed, 32);
            seed[32] = i + j * KYBER_K;
            
            uint8_t buf[384];
            shake128(buf, sizeof(buf), seed, 33);
            
            // Convert bytes to polynomial in the range [0, Q-1]
            for (size_t k = 0; k < KYBER_N; k++) {
                at[i][j][k] = (buf[k] | (buf[k + 128] << 8)) % KYBER_Q;
            }
        }
    }
    
    // Generate vector sp
    for (size_t i = 0; i < KYBER_K; i++) {
        poly_getnoise_eta1(sp[i], buf, i);
    }
    
    // Generate vector ep
    for (size_t i = 0; i < KYBER_K; i++) {
        poly_getnoise_eta2(ep[i], buf, i + KYBER_K);
    }
    
    // Generate error polynomial epp
    poly_getnoise_eta2(epp, buf, 2 * KYBER_K);
    
    // Compute bp = A^T * sp + ep
    for (size_t i = 0; i < KYBER_K; i++) {
        for (size_t j = 0; j < KYBER_N; j++) {
            bp[i][j] = ep[i][j];
            for (size_t k = 0; k < KYBER_K; k++) {
                // Simple polynomial multiplication (for debugging)
                for (size_t l = 0; l < KYBER_N; l++) {
                    if (j >= l) {
                        bp[i][j] = (bp[i][j] + at[i][k][l] * sp[k][j-l]) % KYBER_Q;
                    } else {
                        bp[i][j] = (bp[i][j] - at[i][k][l] * sp[k][j + KYBER_N - l]) % KYBER_Q;
                    }
                }
            }
            bp[i][j] = csubq(bp[i][j]);
        }
    }
    
    // Compute v = pkpv^T * sp + epp + Encode(m)
    poly_frommsg(mp, buf);
    for (size_t j = 0; j < KYBER_N; j++) {
        v[j] = (epp[j] + mp[j]) % KYBER_Q;
        for (size_t k = 0; k < KYBER_K; k++) {
            // Simple polynomial multiplication (for debugging)
            for (size_t l = 0; l < KYBER_N; l++) {
                if (j >= l) {
                    v[j] = (v[j] + pkpv[k][l] * sp[k][j-l]) % KYBER_Q;
                } else {
                    v[j] = (v[j] - pkpv[k][l] * sp[k][j + KYBER_N - l]) % KYBER_Q;
                }
            }
        }
        v[j] = csubq(v[j]);
    }
    
    // Pack ciphertext
    polyvec_compress(ct, bp);
    poly_compress(ct + KYBER_POLYVECBYTES, v);
    
    // Derive shared secret using SHAKE-256
    uint8_t concat[32 + KYBER_CIPHERTEXTBYTES];
    memcpy(concat, buf, 32);
    memcpy(concat + 32, ct, KYBER_CIPHERTEXTBYTES);
    shake256(ss, KYBER_SSBYTES, concat, 32 + KYBER_CIPHERTEXTBYTES);
    
    // Clean up sensitive data
    memset(buf, 0, sizeof(buf));
    memset(sp, 0, sizeof(sp));
    memset(ep, 0, sizeof(ep));
    memset(epp, 0, sizeof(epp));
}

// Decapsulation
void kyber_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint8_t buf[32];
    uint8_t noiseseed[32];
    int16_t s[KYBER_K][KYBER_N], bp[KYBER_K][KYBER_N], v[KYBER_N], mp[KYBER_N];
    
    // Unpack secret key
    polyvec_decompress(s, sk);
    const uint8_t *pk = sk + KYBER_POLYVECBYTES;
    memcpy(noiseseed, sk + KYBER_POLYVECBYTES + KYBER_PUBLICKEYBYTES, 32);
    
    // Unpack ciphertext
    polyvec_decompress(bp, ct);
    poly_decompress(v, ct + KYBER_POLYVECBYTES);
    
    // Compute m = v - s^T * bp
    for (size_t j = 0; j < KYBER_N; j++) {
        int16_t t = 0;
        for (size_t k = 0; k < KYBER_K; k++) {
            // Simple polynomial multiplication (for debugging)
            for (size_t l = 0; l < KYBER_N; l++) {
                if (j >= l) {
                    t = (t + s[k][l] * bp[k][j-l]) % KYBER_Q;
                } else {
                    t = (t - s[k][l] * bp[k][j + KYBER_N - l]) % KYBER_Q;
                }
            }
        }
        mp[j] = (v[j] - t) % KYBER_Q;
        mp[j] = csubq(mp[j]);
    }
    
    // Convert m to message
    poly_tomsg(buf, mp);
    
    // Re-encrypt to verify ciphertext
    uint8_t ct2[KYBER_CIPHERTEXTBYTES];
    uint8_t ss2[KYBER_SSBYTES];
    kyber_encapsulate(ct2, ss2, pk);
    
    // Compare with original ciphertext
    int cmp = 0;
    for (size_t i = 0; i < KYBER_CIPHERTEXTBYTES; i++) {
        cmp |= ct[i] ^ ct2[i];
    }
    
    // If ciphertexts don't match, use a random value
    if (cmp != 0) {
        secure_randombytes(buf, 32);
    }
    
    // Derive shared secret using SHAKE-256
    uint8_t concat[32 + KYBER_CIPHERTEXTBYTES];
    memcpy(concat, buf, 32);
    memcpy(concat + 32, ct, KYBER_CIPHERTEXTBYTES);
    shake256(ss, KYBER_SSBYTES, concat, 32 + KYBER_CIPHERTEXTBYTES);
    
    // Clean up sensitive data
    memset(buf, 0, sizeof(buf));
}

// Example usage
int main() {
    uint8_t pk[KYBER_PUBLICKEYBYTES];
    uint8_t sk[KYBER_SECRETKEYBYTES];
    uint8_t ct[KYBER_CIPHERTEXTBYTES];
    uint8_t ss1[KYBER_SSBYTES];
    uint8_t ss2[KYBER_SSBYTES];
    
    printf("Kyber768 Post-Quantum Cryptography Implementation\n");
    printf("=================================================\n\n");
    
    // Generate keypair
    printf("Generating keypair...\n");
    kyber_keypair(pk, sk);
    printf("Key generation completed.\n");
    
    // Encapsulation
    printf("Performing encapsulation...\n");
    kyber_encapsulate(ct, ss1, pk);
    printf("Encapsulation completed.\n");
    
    // Decapsulation
    printf("Performing decapsulation...\n");
    kyber_decapsulate(ss2, ct, sk);
    printf("Decapsulation completed.\n");
    
    // Verify shared secrets match
    int cmp = 0;
    for (size_t i = 0; i < KYBER_SSBYTES; i++) {
        cmp |= ss1[i] ^ ss2[i];
    }
    
    if (cmp == 0) {
        printf("Success: Shared secrets match!\n");
        
        // Print first few bytes of shared secrets for verification
        printf("Shared secret 1: ");
        for (int i = 0; i < 8; i++) printf("%02x", ss1[i]);
        printf("...\n");
        
        printf("Shared secret 2: ");
        for (int i = 0; i < 8; i++) printf("%02x", ss2[i]);
        printf("...\n");
    } else {
        printf("Error: Shared secrets don't match!\n");
        
        // Print first few bytes of shared secrets for debugging
        printf("Shared secret 1: ");
        for (int i = 0; i < 8; i++) printf("%02x", ss1[i]);
        printf("...\n");
        
        printf("Shared secret 2: ");
        for (int i = 0; i < 8; i++) printf("%02x", ss2[i]);
        printf("...\n");
    }
    
    // Clean up
    memset(pk, 0, sizeof(pk));
    memset(sk, 0, sizeof(sk));
    memset(ct, 0, sizeof(ct));
    memset(ss1, 0, sizeof(ss1));
    memset(ss2, 0, sizeof(ss2));
    
    return 0;
}
