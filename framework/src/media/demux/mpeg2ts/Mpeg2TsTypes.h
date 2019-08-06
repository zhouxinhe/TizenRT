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
