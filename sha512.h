/*
 * sha512.h - simple, portable SHA-512 implementation (C11, procedural)
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */

#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA512_BLOCK_SIZE   128
#define SHA512_DIGEST_SIZE  64

typedef struct {
    uint64_t state[8];
    uint8_t buffer[SHA512_BLOCK_SIZE];
    uint64_t bitlen_high;
    uint64_t bitlen_low;
    size_t buffer_len;
} sha512_ctx;

/* initialize context */
void sha512_init(sha512_ctx *ctx);

/* process input bytes */
void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len);

/* finalize and produce digest (64 bytes) */
void sha512_final(sha512_ctx *ctx, uint8_t out[SHA512_DIGEST_SIZE]);

/* convenience one-shot */
void sha512(uint8_t out[SHA512_DIGEST_SIZE], const uint8_t *data, size_t len);

/* self-test (returns 0 on success, non-zero on failure) */
int sha512_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* SHA512_H */
