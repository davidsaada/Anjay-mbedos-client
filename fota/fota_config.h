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

#ifndef __FOTA_CONFIG_H_
#define __FOTA_CONFIG_H_

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define FOTA_INTERNAL_FLASH_MBED_OS_BD    1
#define FOTA_CUSTOM_MBED_OS_BD            2
#define FOTA_EXTERNAL_BD                  3
#define FOTA_DEFAULT_MBED_OS_BD           4

// on Mbed-OS port, when using internal flash or custom BlockDevices - it is expected for configuration to
//  provide storage start address and size
#if !defined(MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE) || (MBED_CLOUD_CLIENT_FOTA_STORAGE_SIZE == 0)
#error Storage size should be defined and have a nonzero value
#endif

#if !defined(MBED_CLOUD_CLIENT_FOTA_STORAGE_START_ADDR)
#error "MBED_CLOUD_CLIENT_FOTA_STORAGE_START_ADDR must be set"
#endif

#if MBED_CLOUD_CLIENT_FOTA_BLOCK_DEVICE_TYPE == FOTA_EXTERNAL_BD
#ifndef MBED_CLOUD_CLIENT_FOTA_STORAGE_START_ADDR
#define MBED_CLOUD_CLIENT_FOTA_STORAGE_START_ADDR 0
#endif
#endif

#if FOTA_HAS_LEGACY_BOOTLOADER
#ifndef MBED_CLOUD_CLIENT_FOTA_FW_HEADER_EXTERNAL
#error MBED_CLOUD_CLIENT_FOTA_FW_HEADER_EXTERNAL should be defined
#endif
#define MBED_CLOUD_CLIENT_FOTA_FW_HEADER_VERSION 2
#else
#error Currently only legacy bootloader is supported
#endif

#define FOTA_USE_DEVICE_KEY    1
#define FOTA_USE_ENCRYPTED_ONE_TIME_FW_KEY  2

#endif  // MBED_CLOUD_CLIENT_FOTA_ENABLE

#endif  // __FOTA_CONFIG_H_
