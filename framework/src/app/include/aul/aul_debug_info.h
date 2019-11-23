/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __AUL_DEBUG_INFO_H__
#define __AUL_DEBUG_INFO_H__

#include <bundle.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initializes debug information.
 *
 * @return      @c 0 on success,
 *              otherwise a negative error value
 */
int aul_debug_info_init(void);

/**
 * @brief Finalizes debug information.
 *
 * @return      @c 0 on success,
 *              otherwise a negative error value
 */
int aul_debug_info_fini(void);

/**
 * @breif Sets the debug information into the bundle object.
 *
 * @param[in]   src             The bundle object
 * @param[in]   dst             The bundle object
 *
 * @return      @c 0 on success,
 *              otherwise a negative error value
 */
int aul_debug_info_set(bundle *src, bundle *dst);

#ifdef __cplusplus
}
#endif

#endif /* __AUL_DEBUG_INFO_H__ */
