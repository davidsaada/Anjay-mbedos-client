/**
 * @file        bt_01001_v0_1.h
 * @author      Danius Kalvaitis (danius@ovon.io)
 * @brief       Bulk Tainer BT_01001_V0_1 board description file.
 * @date        2020-03-05
 * 
 * @copyright   Copyright (c) 2020 Ovon Technologies Limited
 */

#ifndef BT_01001_V0_1_H
#define BT_01001_V0_1_H

#include "PinNames.h"

// Battery level measurement
#define BT_BATTERY_LVL          PA_0
#define BT_BATTERY_LVL_EN       PA_5

// MAX31855
#define BT_MAX31855_CS          PA_4
#define BT_MAX31855_SCK         PA_1
#define BT_MAX31855_MISO        PA_11
#define BT_MAX31855_PWR         PD_2

// UART port reserved for bootloader
#define BT_BOOT_TX              PA_2
#define BT_BOOT_RX              PA_3

// BG96
#define BT_BG96_RESET           PB_5
#define BT_BG96_RESET_ACT_LVL   0
#define BT_BG96_PWRKEY          PB_8
#define BT_BG96_PWRKEY_ACT_LVL  0
#define BT_BG96_STATUS          PB_9

#define BT_BG96_UART1_TX        PC_4
#define BT_BG96_UART1_RX        PC_5
#define BT_BG96_UART1_CTS       PA_6
#define BT_BG96_UART1_DCD       PA_12
#define BT_BG96_UART1_DTR       PB_0
#define BT_BG96_UART1_RTS       PB_1
#define BT_BG96_UART1_RI        PB_2

#define BT_BG96_UART3_TX        PA_9
#define BT_BG96_UART3_RX        PA_10

#define BT_GPS_ACT_ANT_EN       PA_8

// EPEAS
#define BT_EPEAS_STATUS1        PA_7

// BLE
#define BT_BLE_RESET            PC_6
#define BT_BLE_SOFT_RESET       PC_8
#define BT_BLE_REQ              PC_7
#define BT_BLE_RDY              PC_9

#define BT_BLE_CS               PA_15
#define BT_BLE_SCK              PC_10
#define BT_BLE_MISO             PC_11
#define BT_BLE_MOSI             PC_12

// ISM330
#define BT_SCL                  PB_6
#define BT_SDA                  PB_7

#define BT_ISM330_INT1          PC_13
#define BT_ISM330_INT2          PH_1

#define BT_ISM330_I2C_ADDRESS   0xD4

// EINK display
#define BT_DISP_BUSY            PB_11
#define BT_DISP_RESET           PB_13
#define BT_DISP_DC              PB_14

#define BT_DISP_CS              PB_12
#define BT_DISP_SCK             PB_10
#define BT_DISP_MOSI            PB_15

// Serial interface for debugging
#define BT_DEBUX_RX             PC_0
#define BT_DEBUX_TX             PC_1

// Temperature sensor
#define BT_TEMP_POS             PC_2
#define BT_TEMP_NEG             PC_3

#endif // BT_01001_V0_1_H
