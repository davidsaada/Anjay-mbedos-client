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

#include "fota/fota.h"
#include "fota/fota_crypto.h"
#include "fota/fota_block_device.h"
#include "fota/fota_header_info.h"
#include "fota/fota_user_funcs.h"
#include <stdlib.h>

static bool initialized = false;

typedef struct {
    size_t storage_start_addr;
    size_t curr_storage_addr;
    size_t handled_fw_bytes;
    uint8_t *prog_buff;
    size_t prog_buff_occupancy;
    size_t bd_prog_size;
    size_t aligned_candidate_header_size;
    size_t update_header_bytes_received;
    fota_hash_context_t *payload_digest;
    fota_header_info_t update_header; // TODO: May need to use a different structure for that
} fota_context;

static fota_context *ctx = NULL;

static void free_context(void)
{
    if (!ctx) {
        return;
    }
    free(ctx->prog_buff);
    fota_hash_finish(&ctx->payload_digest);
    free(ctx);
    ctx = NULL;
}

static void init_context(void)
{
    free_context();
    ctx = malloc(sizeof(*ctx));
    FOTA_ASSERT(ctx);
    memset(ctx, 0, sizeof(*ctx));
}

void fota_abort_internal(int ret)
{
    FOTA_TRACE_ERROR("FOTA aborted. Ret code %d", ret);
    free_context();
}

static int erase_as_needed(size_t address, size_t size)
{
    while (size) {
        size_t erase_size;
        int ret = fota_bd_get_erase_size(address, &erase_size);
        if (ret) {
            return ret;
        }
        ret = fota_bd_erase(address, erase_size);
        if (ret) {
            return ret;
        }
        address += erase_size;
        size -= MIN(erase_size, size);
    }

    return FOTA_STATUS_SUCCESS;
}

static int check_erase_candidate(size_t addr)
{
    int ret;
    size_t bd_read_size, read_buf_size;
    uint8_t *read_buf;
    fota_header_info_t header;

    fota_bd_get_read_size(&bd_read_size);
    read_buf_size = FOTA_ALIGN_UP(fota_get_header_size(), bd_read_size);
    read_buf = malloc(read_buf_size);
    if (!read_buf) {
        FOTA_TRACE_ERROR("Out of memory");
        return FOTA_STATUS_OUT_OF_MEMORY;
    }

    ret = fota_bd_read(read_buf, addr, read_buf_size);
    if (ret) {
        goto end;
    }
    ret = fota_deserialize_header(read_buf, read_buf_size, &header);

    // Failure here means that the candidate header is invalid - nothing to do
    if (ret) {
        ret = FOTA_STATUS_SUCCESS;
        goto end;
    }

    FOTA_TRACE_INFO("Valid candidate found - erasing.");

    // Valid candidate header - erase it
    ret = erase_as_needed(addr, read_buf_size);

end:
    free(read_buf);
    return ret;
}

int fota_init(void)
{
    int ret;
    size_t erase_size, start_addr, end_addr, storage_size;

    if (initialized) {
        return FOTA_STATUS_SUCCESS;
    }

    FOTA_TRACE_DEBUG("fota_init");

    ret = fota_bd_init();
    if (ret) {
        FOTA_TRACE_ERROR("fota_bd_init failed, ret %d", ret);
        return ret;
    }

    start_addr = fota_bd_physical_addr_to_logical_addr(MBED_CLOUD_CLIENT_FOTA_STORAGE_START_ADDR);
    ret = fota_bd_get_erase_size(start_addr, &erase_size);
    if (ret) {
        return ret;
    }
    if (start_addr % erase_size) {
        FOTA_TRACE_ERROR("Storage start address (0x%x) not aligned to erase size (0x%x)",
                         start_addr, erase_size);
        return FOTA_STATUS_INVALID_CONFIG;
    }

    end_addr = start_addr + MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE;
    ret = fota_bd_size(&storage_size);
    if (ret) {
        return ret;
    }

    if (end_addr > storage_size) {
        FOTA_TRACE_ERROR("Storage end address (0x%x) exceeds storage size (0x%x)",
                         end_addr, storage_size);
        return FOTA_STATUS_INVALID_CONFIG;
    }

    if (end_addr < storage_size) {
        ret = fota_bd_get_erase_size(end_addr, &erase_size);
        if (ret) {
            return ret;
        }
        if (end_addr % erase_size) {
            FOTA_TRACE_ERROR("Storage end address (0x%x) not aligned to erase size (0x%x)",
                             end_addr, erase_size);
            return FOTA_STATUS_INVALID_CONFIG;
        }
    }

    ret = check_erase_candidate(start_addr);
    if (ret) {
        return ret;
    }

    initialized = true;
    return FOTA_STATUS_SUCCESS;
}

int fota_deinit(void)
{
    FOTA_TRACE_DEBUG("fota_deinit");
    free_context();
    initialized = false;
    return FOTA_STATUS_SUCCESS;
}

int fota_download_start(void)
{
    FOTA_TRACE_DEBUG("fota_download_start");
    if (!initialized) {
        FOTA_TRACE_ERROR("FOTA not initialized");
        return FOTA_STATUS_NOT_INITIALIZED;
    }
    if (ctx) {
        FOTA_TRACE_INFO("Warning: FOTA restarted");
    }
    init_context();

    ctx->storage_start_addr = fota_bd_physical_addr_to_logical_addr(MBED_CLOUD_CLIENT_FOTA_STORAGE_START_ADDR);

    fota_bd_get_program_size(&ctx->bd_prog_size);
    ctx->prog_buff = malloc(ctx->bd_prog_size);
    if (!ctx->prog_buff) {
        FOTA_TRACE_ERROR("Out of memory");
        int ret = FOTA_STATUS_OUT_OF_MEMORY;
        fota_abort_internal(ret);
        return ret;
    }

    ctx->curr_storage_addr = ctx->storage_start_addr;

    fota_hash_start(&ctx->payload_digest);

    return FOTA_STATUS_SUCCESS;
}

static int handle_update_header(size_t *size, const uint8_t **data)
{
    if (ctx->update_header_bytes_received && (ctx->update_header_bytes_received == ctx->update_header.header_size)) {
        return FOTA_STATUS_SUCCESS;
    }

    if (!ctx->update_header_bytes_received) {
        // First received fragment - check magic and update header size. Assume they're contained in fragment
        //fota_header_info_t *header_ptr = (fota_header_info_t *) *data;

        // TODO: Currently force structure size as header size
        // ctx->update_header.header_size = header_ptr->header_size;
        ctx->update_header.header_size = sizeof(ctx->update_header);

        // Currently don't support a case where received header size is larger than the one we have
        if (ctx->update_header.header_size > sizeof(ctx->update_header)) {
            FOTA_TRACE_ERROR("Received update image header has an invalid size");
            return FOTA_STATUS_INVALID_FW_IMAGE;
        }
    }

    uint8_t *dest_ptr = (uint8_t *) &ctx->update_header + ctx->update_header_bytes_received;
    size_t chunk = MIN(*size, ctx->update_header.header_size - ctx->update_header_bytes_received);
    memcpy(dest_ptr, *data, chunk);
    ctx->update_header_bytes_received += chunk;
    *size -= chunk;
    *data += chunk;

    // TODO: Currently force structure size as header size
    ctx->update_header.header_size = sizeof(ctx->update_header);

    if (ctx->update_header_bytes_received < ctx->update_header.header_size) {
        // Still didn't fill the entire header, nothing more to do here
        return FOTA_STATUS_SUCCESS;
    }

    // TODO: Current header needs field translation from BE
    ctx->update_header.magic = FOTA_UINT32_BE(ctx->update_header.magic);
    ctx->update_header.version = FOTA_UINT64_BE(ctx->update_header.version);
    ctx->update_header.fw_size = FOTA_UINT64_BE(ctx->update_header.fw_size);

    if (ctx->update_header.magic != FOTA_UPDATE_HEADER_MAGIC) {
        FOTA_TRACE_ERROR("Received update image has an invalid magic");
        return FOTA_STATUS_INVALID_FW_IMAGE;
    }

    // Now got entire header - handle actual image start

    if (fota_authorize_download()) {
        FOTA_TRACE_ERROR("Download not authorized by application");
        return FOTA_STATUS_DOWNLOAD_NOT_AUTHORIZED;
    }

    ctx->aligned_candidate_header_size = FOTA_ALIGN_UP(fota_get_header_size(), ctx->bd_prog_size);
    ctx->curr_storage_addr += ctx->aligned_candidate_header_size;

    if (ctx->update_header.fw_size + ctx->aligned_candidate_header_size > MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE) {
        FOTA_TRACE_ERROR("Insufficient storage for candidate");
        return FOTA_STATUS_INSUFFICIENT_STORAGE;
    }

    FOTA_TRACE_DEBUG("Update header valid. fw size %llu, version %llu", ctx->update_header.fw_size, ctx->update_header.version);

    FOTA_TRACE_DEBUG("Erasing candidate storage - address 0x%x, size %u",
                     ctx->storage_start_addr, (size_t) ctx->update_header.fw_size + ctx->aligned_candidate_header_size);
    return erase_as_needed(ctx->storage_start_addr, ctx->update_header.fw_size + ctx->aligned_candidate_header_size);
}

int fota_download_fragment(const void *data, size_t size)
{
    int ret;
    const uint8_t *data_ptr = (const uint8_t *) data;

    if (!initialized) {
        FOTA_TRACE_ERROR("FOTA not initialized");
        return FOTA_STATUS_NOT_INITIALIZED;
    }
    if (!ctx) {
        FOTA_TRACE_ERROR("Download not started");
        return FOTA_STATUS_NOT_STARTED;
    }

    FOTA_TRACE_DEBUG("fota_download_fragment: size %d", size);

    ret = handle_update_header(&size, &data_ptr);
    if (ret) {
        goto end;
    }

    if (ctx->handled_fw_bytes + size > ctx->update_header.fw_size) {
        FOTA_TRACE_ERROR("Number of received bytes exceeds FW size");
        ret = FOTA_STATUS_INVALID_FW_IMAGE;
        goto end;
    }

    fota_report_download_progress(ctx->handled_fw_bytes, size, (size_t) ctx->update_header.fw_size);

    ret = fota_hash_update(ctx->payload_digest, data_ptr, size);
    if (ret) {
        goto end;
    }

    while (size) {
        uint32_t chunk, prog_size;
        const uint8_t *prog_from;
        if (!ctx->prog_buff_occupancy && (size >= ctx->bd_prog_size)) {
            // Common case: Take all data from fragment buffer, no need to mess with program buffer
            prog_from = data_ptr;
            chunk = FOTA_ALIGN_DOWN(size, ctx->bd_prog_size);
            prog_size = chunk;
        } else {
            // Less common case: Need to involve program buffer
            prog_from = ctx->prog_buff;
            chunk = MIN(size, ctx->bd_prog_size - ctx->prog_buff_occupancy);
            memcpy(ctx->prog_buff + ctx->prog_buff_occupancy, data_ptr, chunk);
            ctx->prog_buff_occupancy = (ctx->prog_buff_occupancy + chunk) % ctx->bd_prog_size;
            prog_size = ctx->bd_prog_size;
        }
        ctx->handled_fw_bytes += chunk;

        // Program if we have at least one full program unit or at the end of our image
        if (!ctx->prog_buff_occupancy || (ctx->handled_fw_bytes == ctx->update_header.fw_size)) {
            ret = fota_bd_program(prog_from, ctx->curr_storage_addr, prog_size);
            if (ret) {
                goto end;
            }
            ctx->curr_storage_addr += prog_size;
        }
        data_ptr += chunk;
        size -= chunk;
    }

end:
    if (ret) {
        fota_abort_internal(ret);
    }
    return ret;
}

int fota_download_finish(void)
{
    int ret;
    uint8_t hash_buf[FOTA_CRYPTO_HASH_SIZE];
    uint8_t *read_buf = NULL;
    size_t read_addr, left_size, read_buf_size, bd_read_size;
    const size_t min_read_buf_size = 256;

    FOTA_TRACE_DEBUG("fota_download_finish");
    if (!initialized) {
        FOTA_TRACE_ERROR("FOTA not initialized");
        return FOTA_STATUS_NOT_INITIALIZED;
    }
    if (!ctx) {
        FOTA_TRACE_ERROR("Download not started");
        return FOTA_STATUS_NOT_STARTED;
    }

    if (ctx->handled_fw_bytes != ctx->update_header.fw_size) {
        FOTA_TRACE_ERROR("Number of received bytes doesn't match FW size");
        ret = FOTA_STATUS_INVALID_FW_IMAGE;
        goto end;
    }

    fota_report_download_progress(ctx->handled_fw_bytes, 0, ctx->update_header.fw_size);

    ret = fota_hash_result(ctx->payload_digest, hash_buf);
    if (ret) {
        goto end;
    }

    if (memcmp(hash_buf, ctx->update_header.digest, FOTA_CRYPTO_HASH_SIZE)) {
        FOTA_TRACE_ERROR("Image hash mismatch");
        ret = FOTA_STATUS_INVALID_FW_IMAGE;
        goto end;
    }

    fota_hash_finish(&ctx->payload_digest);

    // Check hash on programmed image as well. This will only fail if storage is broken or if we have a bug.

    FOTA_TRACE_DEBUG("Verify image on storage");

    fota_bd_get_read_size(&bd_read_size);
    read_buf_size = FOTA_ALIGN_UP(min_read_buf_size, bd_read_size);
    read_buf = malloc(read_buf_size);
    if (!read_buf) {
        FOTA_TRACE_ERROR("Out of memory");
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        goto end;
    }
    left_size = ctx->update_header.fw_size;
    read_addr = ctx->storage_start_addr + ctx->aligned_candidate_header_size;
    fota_hash_start(&ctx->payload_digest);

    while (left_size) {
        size_t chunk = MIN(left_size, read_buf_size);
        ret = fota_bd_read(read_buf, read_addr, read_buf_size);
        if (ret) {
            goto end;
        }
        ret = fota_hash_update(ctx->payload_digest, read_buf, chunk);
        if (ret) {
            goto end;
        }
        read_addr += chunk;
        left_size -= chunk;
    }

    ret = fota_hash_result(ctx->payload_digest, hash_buf);
    if (ret) {
        goto end;
    }

    if (memcmp(hash_buf, ctx->update_header.digest, FOTA_CRYPTO_HASH_SIZE)) {
        FOTA_TRACE_ERROR("Storage verification failed");
        ret = FOTA_STATUS_STORAGE_WRITE_FAILED;
        goto end;
    }

end:
    if (ret) {
        fota_abort_internal(ret);
    }
    free(read_buf);
    FOTA_TRACE_DEBUG("Done.");

    return ret;
}

int fota_abort(void)
{
    fota_abort_internal(FOTA_STATUS_ABORT_REQUESTED);
    return FOTA_STATUS_SUCCESS;
}

int fota_install_firmware(void)
{
    int ret = FOTA_STATUS_SUCCESS;
    uint8_t *header_buf = NULL;
    size_t header_actual_size;

    if (!initialized) {
        FOTA_TRACE_ERROR("FOTA not initialized");
        return FOTA_STATUS_NOT_INITIALIZED;
    }
    if (!ctx) {
        FOTA_TRACE_ERROR("Download not started");
        return FOTA_STATUS_NOT_STARTED;
    }
    FOTA_TRACE_DEBUG("fota_install_firmware");

    if (fota_authorize_install()) {
        ret = FOTA_STATUS_INSTALL_NOT_AUTHORIZED;
        FOTA_TRACE_ERROR("Installation not authorized by application");
        goto end;
    }

    header_buf = malloc(ctx->aligned_candidate_header_size);
    if (!header_buf) {
        FOTA_TRACE_ERROR("Out of memory");
        ret = FOTA_STATUS_OUT_OF_MEMORY;
        goto end;
    }
    ret = fota_serialize_header(&ctx->update_header, header_buf, ctx->aligned_candidate_header_size, &header_actual_size);
    if (ret) {
        FOTA_TRACE_ERROR("Unable to serialize header");
        ret = FOTA_STATUS_INTERNAL_ERROR;
        goto end;
    }

    FOTA_TRACE_DEBUG("Programming candidate header - address 0x%x, size %u",
                     ctx->storage_start_addr, ctx->aligned_candidate_header_size);

    ret = fota_bd_program(header_buf, ctx->storage_start_addr, ctx->aligned_candidate_header_size);
    if (ret) {
        FOTA_TRACE_ERROR("Unable to program header");
        ret = FOTA_STATUS_STORAGE_WRITE_FAILED;
        goto end;
    }

    FOTA_TRACE_INFO("Firmware installed. Rebooting.");

    free_context();

    // Reboot
    fota_reboot();

end:
    free(header_buf);
    if (ret) {
        fota_abort_internal(ret);
    }
    return ret;
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
