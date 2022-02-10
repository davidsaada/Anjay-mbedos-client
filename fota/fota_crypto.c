// ----------------------------------------------------------------------------
// Copyright 2019-2021 Pelion Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"

#include "fota/fota_crypto.h"
#include "fota/fota_status.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"

#include <stdlib.h>

typedef struct fota_hash_context_s {
    mbedtls_sha256_context sha256_ctx;
} fota_hash_context_t;

#define FOTA_TRACE_TLS_ERR(err) FOTA_TRACE_DEBUG("mbedTLS error %d", err)


int fota_hash_start(fota_hash_context_t **ctx)
{
    FOTA_DBG_ASSERT(ctx);
    int ret;
    *ctx = NULL;

    fota_hash_context_t *hash_ctx = (fota_hash_context_t *) malloc(sizeof(fota_hash_context_t));
    if (!hash_ctx) {
        return FOTA_STATUS_OUT_OF_MEMORY;
    }

    mbedtls_sha256_init(&hash_ctx->sha256_ctx);

    ret = mbedtls_sha256_starts_ret(&hash_ctx->sha256_ctx, 0);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }

    *ctx = hash_ctx;
    return FOTA_STATUS_SUCCESS;
}

int fota_hash_update(fota_hash_context_t *ctx, const uint8_t *buf, uint32_t buf_size)
{
    FOTA_DBG_ASSERT(ctx);
    int ret = mbedtls_sha256_update_ret(&ctx->sha256_ctx, buf, buf_size);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }
    return FOTA_STATUS_SUCCESS;
}

int fota_hash_result(fota_hash_context_t *ctx, uint8_t *hash_buf)
{
    FOTA_DBG_ASSERT(ctx);
    int ret = mbedtls_sha256_finish_ret(&ctx->sha256_ctx, hash_buf);
    if (ret) {
        FOTA_TRACE_TLS_ERR(ret);
        return FOTA_STATUS_INTERNAL_CRYPTO_ERROR;
    }

    return FOTA_STATUS_SUCCESS;
}

void fota_hash_finish(fota_hash_context_t **ctx)
{
    if (ctx && *ctx) {
        mbedtls_sha256_free(&(*ctx)->sha256_ctx);
        free(*ctx);
        *ctx = NULL;
    }
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
