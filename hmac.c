// HMAC_SHA1 implementation
//
// Copyright 2012 kawasima
// Author: Yoshitaka Kawashima
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <string.h>

#include "hmac.h"
#include "apr_sha1.h"

void hmac_sha1(const uint8_t *key, int keyLength,
               const uint8_t *data, int dataLength,
               uint8_t *result, int resultLength) {
    apr_sha1_ctx_t ctx;
    uint8_t hashed_key[APR_SHA1_DIGESTSIZE];
    if (keyLength > 64) {
	// The key can be no bigger than 64 bytes. If it is, we'll hash it down to
	// 20 bytes.
	apr_sha1_init(&ctx);
	apr_sha1_update(&ctx, key, keyLength);
	apr_sha1_final(hashed_key, &ctx);
	key = hashed_key;
	keyLength = APR_SHA1_DIGESTSIZE;
    }

    // The key for the inner digest is derived from our key, by padding the key
    // the full length of 64 bytes, and then XOR'ing each byte with 0x36.
    uint8_t tmp_key[64];
    int i;
    for (i = 0; i < keyLength; ++i) {
	tmp_key[i] = key[i] ^ 0x36;
    }
    memset(tmp_key + keyLength, 0x36, 64 - keyLength);

    // Compute inner digest
    apr_sha1_init(&ctx);
    apr_sha1_update(&ctx, tmp_key, 64);
    apr_sha1_update(&ctx, data, dataLength);

    uint8_t sha[APR_SHA1_DIGESTSIZE];
    apr_sha1_final(sha, &ctx);

    // The key for the outer digest is derived from our key, by padding the key
    // the full length of 64 bytes, and then XOR'ing each byte with 0x5C.
    for (i = 0; i < keyLength; ++i) {
	tmp_key[i] = key[i] ^ 0x5C;
    }
    memset(tmp_key + keyLength, 0x5C, 64 - keyLength);

    // Compute outer digest
    apr_sha1_init(&ctx);
    apr_sha1_update(&ctx, tmp_key, 64);
    apr_sha1_update(&ctx, sha, APR_SHA1_DIGESTSIZE);
    apr_sha1_final(sha, &ctx);

    // Copy result to output buffer and truncate or pad as necessary
    memset(result, 0, resultLength);
    if (resultLength > APR_SHA1_DIGESTSIZE) {
	resultLength = APR_SHA1_DIGESTSIZE;
    }
    memcpy(result, sha, resultLength);

    // Zero out all internal data structures
    memset(hashed_key, 0, sizeof(hashed_key));
    memset(sha, 0, sizeof(sha));
    memset(tmp_key, 0, sizeof(tmp_key));
}
