/*
 * hmac_sha512.h - simple HMAC-SHA512 implementation (C11, procedural)
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025
 */

#ifndef HMAC_SHA512_H
#define HMAC_SHA512_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HMAC_SHA512_BLOCK_SIZE 128
#define HMAC_SHA512_DIGEST_SIZE 64

/* one-shot HMAC-SHA512: computes digest = HMAC(key, data) */
void hmac_sha512(uint8_t out[HMAC_SHA512_DIGEST_SIZE], const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len);

/* built-in known-answer self-test (returns 0 on success, nonzero on fail) */
int hmac_sha512_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* HMAC_SHA512_H */
