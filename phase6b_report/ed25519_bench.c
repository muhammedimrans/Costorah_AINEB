/* Phase 6B RQ2: native Ed25519 capacity, replacing the Python floor from
 * Phase 6.
 *
 * Measures what a production gateway (Rust/Go/C++ all bind the same primitives)
 * can actually do per core:
 *   - raw Ed25519 verify
 *   - verify + SHA-256 over a realistic 422-byte JWT signing input
 *   - signing (for the identity service issuance path)
 *
 * build: gcc -O2 ed25519_bench.c -lcrypto -o ed25519_bench
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

int main(void) {
    /* A JWT signing input of the size measured in Phase 6: 422-byte token,
     * of which the signing input (header.payload) is ~340 bytes. */
    unsigned char msg[340];
    RAND_bytes(msg, sizeof(msg));

    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &key);
    EVP_PKEY_CTX_free(pctx);

    unsigned char sig[64];
    size_t siglen = sizeof(sig);
    {
        EVP_MD_CTX *m = EVP_MD_CTX_new();
        EVP_DigestSignInit(m, NULL, NULL, NULL, key);
        EVP_DigestSign(m, sig, &siglen, msg, sizeof(msg));
        EVP_MD_CTX_free(m);
    }

    /* ---- raw verify throughput ---- */
    const int N = 60000;
    double t0 = now_s();
    for (int i = 0; i < N; i++) {
        EVP_MD_CTX *m = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(m, NULL, NULL, NULL, key);
        if (EVP_DigestVerify(m, sig, siglen, msg, sizeof(msg)) != 1) {
            fprintf(stderr, "verify failed\n");
            return 1;
        }
        EVP_MD_CTX_free(m);
    }
    double verify_ops = N / (now_s() - t0);

    /* ---- verify + base64url decode cost proxy + SHA256 (claims hashing) ---- */
    unsigned char digest[32];
    t0 = now_s();
    for (int i = 0; i < N; i++) {
        EVP_MD_CTX *m = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(m, NULL, NULL, NULL, key);
        EVP_DigestVerify(m, sig, siglen, msg, sizeof(msg));
        EVP_MD_CTX_free(m);
        SHA256(msg, sizeof(msg), digest);
    }
    double full_ops = N / (now_s() - t0);

    /* ---- signing throughput (identity service issuance) ---- */
    const int S = 30000;
    t0 = now_s();
    for (int i = 0; i < S; i++) {
        unsigned char s2[64];
        size_t l2 = sizeof(s2);
        EVP_MD_CTX *m = EVP_MD_CTX_new();
        EVP_DigestSignInit(m, NULL, NULL, NULL, key);
        EVP_DigestSign(m, s2, &l2, msg, sizeof(msg));
        EVP_MD_CTX_free(m);
    }
    double sign_ops = S / (now_s() - t0);

    /* ---- per-verify latency distribution ---- */
    const int L = 20000;
    double *lat = malloc(sizeof(double) * L);
    for (int i = 0; i < L; i++) {
        double a = now_s();
        EVP_MD_CTX *m = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(m, NULL, NULL, NULL, key);
        EVP_DigestVerify(m, sig, siglen, msg, sizeof(msg));
        EVP_MD_CTX_free(m);
        lat[i] = (now_s() - a) * 1e6;
    }
    qsort(lat, L, sizeof(double), cmp_d);

    printf("{\n");
    printf("  \"signing_input_bytes\": %zu,\n", sizeof(msg));
    printf("  \"raw_verify_per_s_per_core\": %.0f,\n", verify_ops);
    printf("  \"verify_plus_sha256_per_s_per_core\": %.0f,\n", full_ops);
    printf("  \"sign_per_s_per_core\": %.0f,\n", sign_ops);
    printf("  \"verify_p50_us\": %.2f,\n", lat[L / 2]);
    printf("  \"verify_p99_us\": %.2f,\n", lat[(int)(L * 0.99)]);
    printf("  \"verify_p999_us\": %.2f,\n", lat[(int)(L * 0.999)]);
    printf("  \"openssl_version\": \"%s\"\n", OpenSSL_version(OPENSSL_VERSION));
    printf("}\n");

    free(lat);
    EVP_PKEY_free(key);
    return 0;
}
