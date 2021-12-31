/**
 * @file        boards.h
 * @author      Danius Kalvaitis (danius@ovon.io)
 * @brief       Board definitions file
 * @date        2020-03-05
 * 
 * @copyright   Copyright (c) 2020 Ovon Technologies Limited
 */

#ifndef BOARDS_H
#define BOARDS_H

#if defined(BT_01001_V0_0)
#include "bt_01001_v0_0.h"
#elif defined(BT_01001_V0_1)
#include "bt_01001_v0_1.h"
#elif defined(BT_01001_V0_2)
#include "bt_01001_v0_2.h"
#else
#error Board is not defined!
#endif

#endif // BOARDS_H
