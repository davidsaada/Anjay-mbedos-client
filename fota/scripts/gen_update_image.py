# SPDX-License-Identifier: Apache-2.0
# Copyright 2019-2022 Pelion Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Generate the binary image to be used by FOTA
"""

import binascii
import struct
from typing import Optional



def make_firmware_package(binary: bytes,
                          magic: bytes = b'ANJAY_FW',
                          crc: Optional[int] = None,
                          force_error: FirmwareUpdateForcedError = FirmwareUpdateForcedError.NoError,
                          version: int = 1):
    assert len(magic) == 8

    if crc is None:
        crc = binascii.crc32(binary)

    meta = struct.pack('>8sHHI', magic, version, force_error, crc)
    return meta + binary


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Create firmware package from executable.')
    parser.add_argument('-i', '--in-file',
                        help='Path to the raw binary application. Default: stdin',
                        default='/dev/stdin')
    parser.add_argument('-o', '--out-file',
                        help='Path to generated FOTA binary. Default: stdout',
                        default='/dev/stdout')
    parser.add_argument('-v', '--version',
                        type=int,
                        help='Firmware version (integer). Default: current epoch',
                        default=1)

    args = parser.parse_args()

    with open(args.in_file, 'rb') as in_file, open(args.out_file, 'wb') as out_file:
        out_file.write(make_firmware_package(in_file.read(),
                                             magic=args.magic.encode('ascii'),
                                             crc=args.crc,
                                             force_error=args.force_error,
                                             version=args.version))
