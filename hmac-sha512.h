/*
 * hmac_sha512.h - simple HMAC-SHA512 implementation (C11, procedural)
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

#ifndef _HMAC_SHA512_H
#define _HMAC_SHA512_H

#include <stdint.h>
#include <stddef.h>

#include "sha512.h"

#define HMAC_SHA512_BLOCK_SIZE 128
#define HMAC_SHA512_DIGEST_SIZE 64

void hmac_sha512(uint8_t out[HMAC_SHA512_DIGEST_SIZE], const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len);

#endif
