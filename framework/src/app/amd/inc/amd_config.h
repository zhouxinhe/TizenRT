/*
 * Copyright (c) 2015 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
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

#ifndef __AMD_CONFIG_H__
#define __AMD_CONFIG_H__

typedef enum {
	TIZEN_PROFILE_UNKNOWN = 0,
	TIZEN_PROFILE_MOBILE = 0x1,
	TIZEN_PROFILE_WEARABLE = 0x2,
	TIZEN_PROFILE_TV = 0x4,
	TIZEN_PROFILE_IVI = 0x8,
	TIZEN_PROFILE_COMMON = 0x10,
} tizen_profile_t;

tizen_profile_t _config_get_tizen_profile(void);

#define TIZEN_FEATURE_TERMINATE_UNMANAGEABLE_APP \
	(!(_config_get_tizen_profile() & (TIZEN_PROFILE_TV)))
#define TIZEN_FEATURE_BLOCK_INPUT \
	(!(_config_get_tizen_profile() & (TIZEN_PROFILE_TV | TIZEN_PROFILE_IVI)))
#define TIZEN_FEATURE_AUTO_ROTATION \
	(!(_config_get_tizen_profile() & (TIZEN_PROFILE_TV | TIZEN_PROFILE_IVI)))

unsigned int _config_get_onboot_interval(void);
unsigned int _config_get_fg_timeout(void);
int _config_init(void);
void _config_fini(void);

#endif /* __AMD_CONFIG_H__ */
