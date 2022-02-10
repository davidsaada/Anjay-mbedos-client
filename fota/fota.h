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

#ifndef __FOTA_H_
#define __FOTA_H_

#include "fota/fota_config.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#include "fota/fota_base.h"
#include "fota/fota_status.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize FOTA.
 *
 * This method should be called once on system startup.
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_init(void);

/*
 * Deinitialize FOTA.
 *
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_deinit(void);

/*
 * Start FOTA download
 *
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_download_start(void);

/*
 * Handle a received FOTA fragment
 * \param[in] data fragment data
 * \param[in] size fragment size
 *
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_download_fragment(const void *data, size_t size);

/*
 * Finish FOTA download
 *
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_download_finish(void);

/*
 * Abort FOTA
 *
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_abort(void);

/*
 * Install firmware downloaded by FOTA
 * Note: On success, this will reset the board.
 *
 * \return FOTA_STATUS_SUCCESS on success
 */
int fota_install_firmware(void);

#ifdef __cplusplus
}
#endif

#endif  // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#endif // __FOTA_H_
