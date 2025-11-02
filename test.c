#include <stdio.h>
#include <string.h>

#include "sha512.h"

int main(void)
{
    const char *msg = "The quick brown fox jumps over the lazy dog";
    uint8_t digest[SHA512_DIGEST_SIZE];

    sha512(digest, (const uint8_t *)msg, strlen(msg));

    for (size_t i = 0; i < SHA512_DIGEST_SIZE; ++i)
        printf("%02x", digest[i]);
    printf("\n");

    return sha512_selftest();
}
