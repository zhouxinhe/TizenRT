/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __AMD_API_CONFIG_H__
#define __AMD_API_CONFIG_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	AMD_TIZEN_PROFILE_UNKNOWN = 0,
	AMD_TIZEN_PROFILE_MOBILE = 0x1,
	AMD_TIZEN_PROFILE_WEARABLE = 0x2,
	AMD_TIZEN_PROFILE_TV = 0x4,
	AMD_TIZEN_PROFILE_IVI = 0x8,
	AMD_TIZEN_PROFILE_COMMON = 0x10,
} amd_tizen_profile_t;

amd_tizen_profile_t amd_config_get_tizen_profile(void);

#ifdef __cplusplus
}
#endif

#endif /* __AMD_API_CONFIG_H__ */
