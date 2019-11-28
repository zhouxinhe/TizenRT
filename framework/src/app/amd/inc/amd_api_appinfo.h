/*
 * Copyright (c) 2017 Samsung Electronics Co., Ltd All Rights Reserved
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

#pragma once

#include <sys/types.h>
#include <stdbool.h>

typedef enum _amd_appinfo_type {
	AMD_AIT_NAME = 0,
	AMD_AIT_EXEC,
	AMD_AIT_PKGTYPE,
	AMD_AIT_ONBOOT, /* start on boot: boolean */
	AMD_AIT_RESTART, /* auto restart: boolean */
	AMD_AIT_MULTI,
	AMD_AIT_HWACC,
	AMD_AIT_PERM,
	AMD_AIT_PKGID,
	AMD_AIT_PRELOAD,
	AMD_AIT_STATUS,
	AMD_AIT_POOL,
	AMD_AIT_COMPTYPE,
	AMD_AIT_TEP,
	AMD_AIT_MOUNTABLE_PKG,
	AMD_AIT_STORAGE_TYPE,
	AMD_AIT_BG_CATEGORY,
	AMD_AIT_LAUNCH_MODE,
	AMD_AIT_GLOBAL,
	AMD_AIT_EFFECTIVE_APPID,
	AMD_AIT_TASKMANAGE,
	AMD_AIT_VISIBILITY,
	AMD_AIT_APPTYPE,
	AMD_AIT_ROOT_PATH,
	AMD_AIT_SPLASH_SCREEN,
	AMD_AIT_SPLASH_SCREEN_DISPLAY,
	AMD_AIT_API_VERSION,
	AMD_AIT_ENABLEMENT,
	AMD_AIT_COOLDOWN,
	AMD_AIT_SYSTEM,
	AMD_AIT_IME,
	AMD_AIT_MAX
} amd_appinfo_type;

typedef struct appinfo *amd_appinfo_h;
typedef struct appinfo_splash_image *amd_appinfo_splash_image_h;

#define APP_TYPE_SERVICE	"svcapp"
#define APP_TYPE_UI		"uiapp"
#define APP_TYPE_WIDGET		"widgetapp"
#define APP_TYPE_WATCH		"watchapp"

#define APP_ENABLEMENT_MASK_ACTIVE      0x1

typedef void (*amd_appinfo_iter_callback)(void *user_data,
		const char *filename, amd_appinfo_h h);
int amd_appinfo_insert(uid_t uid, const char *pkgid);
amd_appinfo_h amd_appinfo_find(uid_t caller_uid, const char *appid);
const char *amd_appinfo_get_value(amd_appinfo_h h, amd_appinfo_type type);
const void *amd_appinfo_get_ptr_value(amd_appinfo_h h, amd_appinfo_type type);
int amd_appinfo_get_int_value(amd_appinfo_h h, amd_appinfo_type type, int *val);
int amd_appinfo_get_boolean(amd_appinfo_h h, amd_appinfo_type type, bool *val);
int amd_appinfo_set_value(amd_appinfo_h h, amd_appinfo_type type,
		const char *val);
int amd_appinfo_set_ptr_value(amd_appinfo_h h, amd_appinfo_type type,
		void *val);
int amd_appinfo_set_int_value(amd_appinfo_h h, amd_appinfo_type type, int val);
void amd_appinfo_foreach(uid_t uid, amd_appinfo_iter_callback cb,
		void *user_data);
int amd_appinfo_load(uid_t uid);
void amd_appinfo_unload(uid_t uid);
amd_appinfo_splash_image_h amd_appinfo_find_splash_image(amd_appinfo_h h,
		const char *name, bool landscape);
const char *amd_appinfo_splash_image_get_source(amd_appinfo_splash_image_h h);
const char *amd_appinfo_splash_image_get_type(amd_appinfo_splash_image_h h);
int amd_appinfo_splash_image_get_indicator_display(
		amd_appinfo_splash_image_h h);
int amd_appinfo_splash_image_get_color_depth(amd_appinfo_splash_image_h h);
bool amd_appinfo_is_pkg_updating(const char *pkgid);
int amd_appinfo_get_cert_visibility(const char *pkgid, uid_t uid);
