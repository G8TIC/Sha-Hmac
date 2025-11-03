/*
 * hmac_sha512.c - simple HMAC-SHA512 implementation (C11, procedural)
 *
 * SPDX-License-Identifier: MIT
 * Copyright (C) 2025 Mike Tubby G8TIC mike@tubby.org and contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 *
 */

#include <stdio.h>
#include <string.h>

#include "hmac-sha512.h"
#include "sha512.h"

/*
 * HMAC algorithm (RFC 2104 / FIPS 198-1):
 *
 *   HMAC(K, m) = SHA512((K ⊕ opad) || SHA512((K ⊕ ipad) || m))
 *
 */
void hmac_sha512(uint8_t out[HMAC_SHA512_DIGEST_SIZE], const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len)
{
    uint8_t key_block[HMAC_SHA512_BLOCK_SIZE];
    uint8_t inner_hash[HMAC_SHA512_DIGEST_SIZE];
    uint8_t ipad[HMAC_SHA512_BLOCK_SIZE];
    uint8_t opad[HMAC_SHA512_BLOCK_SIZE];
    size_t i;

    /* Step 1: shorten long keys */
    if (key_len > HMAC_SHA512_BLOCK_SIZE) {
        sha512(key_block, key, key_len);
        memset(key_block + HMAC_SHA512_DIGEST_SIZE, 0,
               HMAC_SHA512_BLOCK_SIZE - HMAC_SHA512_DIGEST_SIZE);
    } else {
        memcpy(key_block, key, key_len);
        if (key_len < HMAC_SHA512_BLOCK_SIZE)
            memset(key_block + key_len, 0, HMAC_SHA512_BLOCK_SIZE - key_len);
    }

    /* Step 2: compute inner and outer pad */
    for (i = 0; i < HMAC_SHA512_BLOCK_SIZE; ++i) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    /* Step 3: inner hash = SHA512(ipad || data) */
    {
        sha512_ctx ctx;
        sha512_init(&ctx);
        sha512_update(&ctx, ipad, HMAC_SHA512_BLOCK_SIZE);
        sha512_update(&ctx, data, data_len);
        sha512_final(&ctx, inner_hash);
    }

    /* Step 4: outer hash = SHA512(opad || inner_hash) */
    {
        sha512_ctx ctx;
        sha512_init(&ctx);
        sha512_update(&ctx, opad, HMAC_SHA512_BLOCK_SIZE);
        sha512_update(&ctx, inner_hash, HMAC_SHA512_DIGEST_SIZE);
        sha512_final(&ctx, out);
    }

    /* clear sensitive data */
    memset(key_block, 0, sizeof(key_block));
    memset(inner_hash, 0, sizeof(inner_hash));
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
}

