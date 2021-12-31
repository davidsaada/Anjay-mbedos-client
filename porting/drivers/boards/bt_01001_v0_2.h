/**
 * @file        bt_01001_v0_2.h
 * @author      Danius Kalvaitis (danius@ovon.io)
 * @brief       Bulk Tainer BT_01001_V0_2 board description file.
 * @date        2020-03-31
 * 
 * @copyright   Copyright (c) 2020 Ovon Technologies Limited
 */

#ifndef BT_01001_V0_2_H
#define BT_01001_V0_2_H

#include "PinNames.h"
#include "stm32l4xx_hal.h"
#include "stm32l4xx_hal_pwr_ex.h"

// QSPI Flash
#define BT_QSPI_SCK             PA_3
#define BT_QSPI_CS              PB_11
#define BT_QSPI_IO0             PB_1
#define BT_QSPI_IO1             PB_0
#define BT_QSPI_IO2             PA_7
#define BT_QSPI_IO3             PA_6

// SPI instance share by MAX31855, E-Ink and BLE module
#define BT_SCK                  PB_10
#define BT_MISO                 PC_2
#define BT_MOSI                 PC_3

// Battery level measurement
#define BT_BATTERY_LVL          PA_4
#define BT_BATTERY_LVL_EN       PB_12

// MAX31855
#define BT_MAX31855_CS          PB_8
#define BT_MAX31855_PWR         PB_5

// UART port reserved for bootloader
#define BT_BOOT_TX              PC_10
#define BT_BOOT_RX              PC_11

// BG96
#define BT_BG96_RESET           PC_7
#define BT_BG96_PWRKEY          PC_8
#define BT_BG96_PIN_ACT_LVL     1

#define BT_BG96_UART1_TX        PA_9
#define BT_BG96_UART1_RX        PA_10
#define BT_BG96_UART1_CTS       PA_11
#define BT_BG96_UART1_DCD       PA_15
#define BT_BG96_UART1_DTR       PB_4
#define BT_BG96_UART1_RTS       PA_12
#define BT_BG96_UART1_RI        PA_8

#define BT_BG96_UART3_TX        PC_12
#define BT_BG96_UART3_RX        PD_2

#define BT_GPS_ACT_ANT_EN       PC_6
#define BT_GPS_ACT_ANT_ACT_LVL  0

// EPEAS
#define BT_EPEAS_STATUS1        PC_5

// BLE
#define BT_BLE_RESET            PB_9
#define BT_BLE_SOFT_RESET       PB_15
#define BT_BLE_REQ              PB_14
#define BT_BLE_RDY              PC_9

#define BT_BLE_SLEEP            PH_0
#define BT_BLE_CS               PH_1

// ISM330
#define BT_SCL                  PB_6
#define BT_SDA                  PB_7

#define BT_ISM330_INT1          PC_13
#define BT_ISM330_PWR_INT1_PORT PWR_GPIO_C
#define BT_ISM330_PWR_INT1_PIN  GPIO_PIN_13
#define BT_ISM330_PWR_INT1_WKUP_PIN PWR_WAKEUP_PIN2_HIGH
#define BT_ISM330_INT2          PA_0

#define BT_ISM330_I2C_ADDRESS   0xD4

// EINK display
#define BT_DISP_BUSY            PA_5
#define BT_DISP_RESET           PC_4
#define BT_DISP_DC              PB_2

#define BT_DISP_CS              PB_13

// Serial interface for debugging
#define BT_DEBUX_RX             PC_0
#define BT_DEBUX_TX             PC_1

// Temperature sensor
#define BT_THERMOCOUPLE_SWITCH  PA_2

#endif // BT_01001_V0_2_H
