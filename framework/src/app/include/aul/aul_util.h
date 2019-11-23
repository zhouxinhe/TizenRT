/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <unistd.h>
#include <dlog.h>
#include <tzplatform_config.h>

#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

#undef LOG_TAG
#define LOG_TAG "AUL"

#define _E(fmt, arg...) LOGE(fmt, ##arg)
#define _D(fmt, arg...) LOGD(fmt, ##arg)
#define _W(fmt, arg...) LOGW(fmt, ##arg)
#define _I(fmt, arg...) LOGI(fmt, ##arg)

#define AUL_UTIL_PID -2
#define MAX_LOCAL_BUFSZ 128
#define MAX_PACKAGE_STR_SIZE 512
#define MAX_PID_STR_BUFSZ 20
#define MAX_UID_STR_BUFSZ 20
#define REGULAR_UID_MIN 5000
#define MAX_RUNNING_INSTANCE 10000

typedef enum {
	TIZEN_PROFILE_UNKNOWN = 0,
	TIZEN_PROFILE_MOBILE = 0x1,
	TIZEN_PROFILE_WEARABLE = 0x2,
	TIZEN_PROFILE_TV = 0x4,
	TIZEN_PROFILE_IVI = 0x8,
	TIZEN_PROFILE_COMMON = 0x10,
} tizen_profile_t;

tizen_profile_t _get_tizen_profile(void);

#define TIZEN_FEATURE_SOCKET_TIMEOUT (_get_tizen_profile() & TIZEN_PROFILE_TV)
#define TIZEN_FEATURE_SHARE_PANEL (_get_tizen_profile() & TIZEN_PROFILE_MOBILE)
