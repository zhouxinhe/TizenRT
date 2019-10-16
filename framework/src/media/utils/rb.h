/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#ifndef _RB_H_
#define _RB_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IDX_MASK (SIZE_MAX >> 1)
#define MSB_MASK (~IDX_MASK)    /* also the maximum value of the buffer depth */

/* ring buffer structure */
struct rb_s {
	void *buf;                  /* pointer to the buffer allocated */
	size_t depth;               /* maximum size of the ring buffer */
	volatile size_t rd_idx;     /* reading index, MSB is used for the 'mirror' flag */
	volatile size_t wr_idx;     /* writing index, MSB is used for the 'mirror' flag */
};

typedef struct rb_s  rb_t;
typedef struct rb_s *rb_p;

/**
 * @brief  Initialize the ring-buffer. Allocate necessary memory for the buffer.
 * @param  rbp: Pointer to the ring-buffer object
 * @param  size: Maximum size in bytes of the buffer
 * @return true on success, false on failure.
 */
bool rb_init(rb_p rbp, size_t size);

/**
 * @brief  Release the ring-buffer object. Deallocate the buffer memory.
 * @param  rbp: Pointer to the ring-buffer object
 */
void rb_free(rb_p rbp);

/**
 * @brief  Get data bytes in the ring-buffer
 * @param  rbp: Pointer to the ring-buffer object
 * @return num of data in bytes
 */
size_t rb_used(rb_p rbp);

/**
 * @brief  Get free space in bytes in the ring-buffer
 * @param  rbp: Pointer to the ring-buffer object
 * @return num of free space in bytes
 */
size_t rb_avail(rb_p rbp);

/**
 * @brief  Write data to the ring-buffer.
 * @param  rbp: Pointer to the ring-buffer object
 * @param  ptr: Pointer of the data to be written to the buffer
 * @param  len: length of the data to be written
 * @return size of data be written, range[0, len]
 */
size_t rb_write(rb_p rbp, const void *ptr, size_t len);

/**
 * @brief  Read from the ring-buffer header
 * @param  rbp: Pointer to the ring-buffer object
 * @param  ptr: Pointer to the buffer saving read data
 * @param  len: length of the data wanted
 * @return size of data read(rd_idx increased), range[0, len]
 */
size_t rb_read(rb_p rbp, void *ptr, size_t len);

/**
 * @brief  Copy data from the ring-buffer at the given offset,
 *         rd_idx will not be increased.
 * @param  rbp: Pointer to the ring-buffer object
 * @param  ptr: Pointer to the buffer saving data
 * @param  len: length of the data wanted
 * @param  offset: offset from rd_idx started to copy.
 * @return size of data actually be copied, range[0, len].
 */
size_t rb_copy(rb_p rbp, void *ptr, size_t len, size_t offset);

/**
 * @brief  Skip the given lenght of data from ring-buffer header
 * @param  rbp: Pointer to the ring-buffer object
 * @param  len: length of the data to be skipped
 * @return size of data skipped(rd_idx increased), range[0, len].
 */
size_t rb_skip(rb_p rbp, size_t len);

/**
 * @brief  Reset ring-buffer, data in ring-buffer will be dropped.
 * @param  rbp: Pointer to the ring-buffer object
 * @return true on success, otherwise false.
 */
bool rb_reset(rb_p rbp);

#ifdef __cplusplus
}
#endif
#endif

