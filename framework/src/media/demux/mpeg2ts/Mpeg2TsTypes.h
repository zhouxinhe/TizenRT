/******************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef	__MPEG2_TS_TYPES_H__
#define __MPEG2_TS_TYPES_H__

#include <stdio.h>
#include <stdint.h>

// Default initialize value
#define INFINITY                (~0)
// Invalid PID value
#define INVALID_PID             (0x1FFF)
// Continuity counter module value
#define CONTINUITY_COUNTER_MOD  (16)

// Types definition
typedef int16_t  ts_pid_t;      // TS packet pid
typedef uint8_t  table_id_t;    // table id
typedef int32_t  stream_id_t;   // stream id
typedef uint16_t prog_num_t;    // program number
typedef uint32_t crc32_t;       // CRC32

#endif /* __MPEG2_TS_TYPES_H__ */
