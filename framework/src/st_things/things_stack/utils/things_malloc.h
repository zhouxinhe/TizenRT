/****************************************************************************
 *
 * Copyright 2017 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef THINGS_MALLOC_H_
#define THINGS_MALLOC_H_

#include <tinyara/config.h>
#include <stdio.h>

#ifndef ENABLE_THINGS_MALLOC

#if (CONFIG_MM_NHEAPS >= 3)
#define things_malloc(x) malloc_at(2, x)
#define things_free(x) free(x)
#define things_realloc(x, y) realloc_at(2, x, y)
#define things_calloc(x, y) calloc_at(2, x, y)
#else
#define things_malloc(x) malloc(x)
#define things_free(x) free(x)
#define things_realloc(x, y) realloc(x, y)
#define things_calloc(x, y) calloc(x, y)
#endif

#else

extern void *things_malloc(size_t size);
extern void *things_realloc(void *ptr, size_t size);
extern void *things_calloc(size_t num, size_t size);
extern void things_free(void *ptr);
#endif

#endif							/* THINGS_MALLOC_H_ */
