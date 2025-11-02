#include <stdio.h>
#include <string.h>
#include "sha256.h"
#include "sha512.h"
#include "hmac_sha256.h"
#include "hmac_sha512.h"

static void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
}

int main(void)
{
    int fail_count = 0;

    printf("=== Running built-in self-tests ===\n");

    fail_count += sha256_selftest();
    fail_count += sha512_selftest();
    fail_count += hmac_sha256_selftest();
    fail_count += hmac_sha512_selftest();

    if (fail_count == 0) {
        printf("All self-tests passed!\n\n");
    } else {
        printf("Some self-tests failed (%d failures)\n\n", fail_count);
    }

    /* === Example usage === */
    const char *msg = "The quick brown fox jumps over the lazy dog";
    uint8_t sha256_digest[SHA256_DIGEST_SIZE];
    uint8_t sha512_digest[SHA512_DIGEST_SIZE];
    uint8_t hmac256_digest[HMAC_SHA256_DIGEST_SIZE];
    uint8_t hmac512_digest[HMAC_SHA512_DIGEST_SIZE];
    const uint8_t key[] = "secret";

    printf("Message: '%s'\n\n", msg);

    sha256(sha256_digest, (const uint8_t *)msg, strlen(msg));
    printf("SHA-256: ");
    print_hex(sha256_digest, SHA256_DIGEST_SIZE);
    printf("\n");

    sha512(sha512_digest, (const uint8_t *)msg, strlen(msg));
    printf("SHA-512: ");
    print_hex(sha512_digest, SHA512_DIGEST_SIZE);
    printf("\n");

    hmac_sha256(hmac256_digest, key, sizeof(key)-1, (const uint8_t *)msg, strlen(msg));
    printf("HMAC-SHA256: ");
    print_hex(hmac256_digest, HMAC_SHA256_DIGEST_SIZE);
    printf("\n");

    hmac_sha512(hmac512_digest, key, sizeof(key)-1, (const uint8_t *)msg, strlen(msg));
    printf("HMAC-SHA512: ");
    print_hex(hmac512_digest, HMAC_SHA512_DIGEST_SIZE);
    printf("\n");

    return fail_count;
}
