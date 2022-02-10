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

#include "fota/fota_user_funcs.h"
#include "fota/fota_status.h"
#ifdef __MBED__
#include "mbed_power_mgmt.h"
#endif

#include <stdio.h>

int fota_authorize_download(void)
{
    return FOTA_STATUS_SUCCESS;
}

int fota_authorize_install(void)
{
    return FOTA_STATUS_SUCCESS;
}

void fota_report_download_progress(size_t downloaded_size, size_t current_chunk_size, size_t total_size)
{
    static const size_t  print_range_percent = 5;

    if (downloaded_size == 0) {
        printf("Download firmware started. Firmware size is %u bytes.\n", total_size);
    }

    total_size /= 100;
    // In case total size is less then 100B return without printing progress
    if (total_size == 0) {
        return;
    }

    size_t progress = (downloaded_size + current_chunk_size) / total_size;
    size_t prev_progress = downloaded_size / total_size;

    if (downloaded_size == 0 || ((progress / print_range_percent) > (prev_progress / print_range_percent))) {
        printf("Downloading firmware. %u%c\n", progress, '%');
    }
    if (downloaded_size + current_chunk_size == total_size) {
        printf("Download complete.\n");
    }
}

void fota_reboot(void)
{
#ifdef __MBED__
    system_reset();
#endif
}

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE
