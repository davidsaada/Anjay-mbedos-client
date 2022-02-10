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

#ifndef __FOTA_STATUS_H_
#define __FOTA_STATUS_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FOTA_STATUS_SUCCESS                             =  0,  /**< all good */
    FOTA_STATUS_INSUFFICIENT_STORAGE                = -1,  /**< Insufficient storage on a device for saving update candidate */
    FOTA_STATUS_OUT_OF_MEMORY                       = -2,  /**< Not enough RAM */
    FOTA_STATUS_STORAGE_WRITE_FAILED                = -3,  /**< Storage write error */
    FOTA_STATUS_STORAGE_READ_FAILED                 = -4,  /**< Storage read error */
    FOTA_STATUS_FW_INSTALLATION_FAILED              = -5,  /**< Update failed at installation phase */
    FOTA_STATUS_INTERNAL_ERROR                      = -5,  /**< Non-specific internal error */
    FOTA_STATUS_NOT_FOUND                           = -7,  /**< Expected asset is not found in NVM */
    FOTA_STATUS_INVALID_ARGUMENT                    = -8,  /**< Invalid argument was received */
    FOTA_STATUS_NOT_INITIALIZED                     = -9,  /**< FOTA not initialized */
    FOTA_STATUS_NOT_STARTED                         = -10, /**< FOTA download not started */
    FOTA_STATUS_INTERNAL_CRYPTO_ERROR               = -11, /**< FOTA internal crypto error */
    FOTA_STATUS_INVALID_FW_IMAGE                    = -12, /**< Invalid firmware image */
    FOTA_STATUS_ABORT_REQUESTED                     = -13, /**< FOTA abort requested from service */
    FOTA_STATUS_DOWNLOAD_NOT_AUTHORIZED             = -14, /**< FOTA download not authorized by application */
    FOTA_STATUS_INSTALL_NOT_AUTHORIZED              = -15, /**< FOTA install not authorized by application */
    FOTA_STATUS_INVALID_CONFIG                      = -16, /**< FOTA's configuration is invalid */
} fota_status_e;


#ifdef __cplusplus
}
#endif

#endif  // __FOTA_STATUS_H_
