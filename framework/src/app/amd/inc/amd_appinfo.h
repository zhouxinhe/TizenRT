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

#pragma once

#include <sys/types.h>
#include <glib.h>
#include <stdbool.h>

#define AIT_START 0
enum appinfo_type {
	AIT_NAME = AIT_START,
	AIT_EXEC,
	AIT_PKGTYPE,
	AIT_ONBOOT, /* start on boot: boolean */
	AIT_RESTART, /* auto restart: boolean */
	AIT_MULTI,
	AIT_HWACC,
	AIT_PERM,
	AIT_PKGID,
	AIT_PRELOAD,
	AIT_STATUS,
	AIT_POOL,
	AIT_COMPTYPE,
	AIT_TEP,
	AIT_MOUNTABLE_PKG,
	AIT_STORAGE_TYPE,
	AIT_BG_CATEGORY,
	AIT_LAUNCH_MODE,
	AIT_GLOBAL,
	AIT_EFFECTIVE_APPID,
	AIT_TASKMANAGE,
	AIT_VISIBILITY,
	AIT_APPTYPE,
	AIT_ROOT_PATH,
	AIT_SPLASH_SCREEN,
	AIT_SPLASH_SCREEN_DISPLAY,
	AIT_API_VERSION,
	AIT_ENABLEMENT,
	AIT_COOLDOWN,
	AIT_SYSTEM,
	AIT_IME,
	AIT_MAX
};

struct appinfo {
	char *val[AIT_MAX];
};

struct appinfo_splash_screen {
	GHashTable *portrait;
	GHashTable *landscape;
};

struct appinfo_splash_image {
	char *src;
	char *type;
	char *indicatordisplay;
	char *color_depth;
};

#define APP_TYPE_SERVICE	"svcapp"
#define APP_TYPE_UI		"uiapp"
#define APP_TYPE_WIDGET		"widgetapp"
#define APP_TYPE_WATCH		"watchapp"

#define APP_ENABLEMENT_MASK_ACTIVE	0x1
#define APP_ENABLEMENT_MASK_REQUEST	0x2

typedef void (*appinfo_iter_callback)(void *user_data,
		const char *filename, struct appinfo *c);
int _appinfo_init(void);
void _appinfo_fini(void);
int _appinfo_insert(uid_t uid, const char *pkgid);
struct appinfo *_appinfo_find(uid_t caller_uid, const char *appid);
const char *_appinfo_get_value(const struct appinfo *c, enum appinfo_type type);
const void *_appinfo_get_ptr_value(const struct appinfo *c,
		enum appinfo_type type);
int _appinfo_get_int_value(const struct appinfo *c, enum appinfo_type type,
		int *val);
int _appinfo_get_boolean(const struct appinfo *c, enum appinfo_type type,
			bool *val);
int _appinfo_set_value(struct appinfo *c, enum appinfo_type, const char *val);
int _appinfo_set_ptr_value(struct appinfo *c, enum appinfo_type, void *val);
int _appinfo_set_int_value(struct appinfo *c, enum appinfo_type type, int val);
void _appinfo_foreach(uid_t uid, appinfo_iter_callback cb, void *user_data);
int _appinfo_load(uid_t uid);
void _appinfo_unload(uid_t uid);
struct appinfo_splash_image *_appinfo_find_splash_image(struct appinfo *c,
		const char *name, bool landscape);
const char *_appinfo_splash_image_get_source(struct appinfo_splash_image *s);
const char *_appinfo_splash_image_get_type(struct appinfo_splash_image *s);
int _appinfo_splash_image_get_indicator_display(struct appinfo_splash_image *s);
int _appinfo_splash_image_get_color_depth(struct appinfo_splash_image *s);
bool _appinfo_is_pkg_updating(const char *pkgid);
int _appinfo_get_cert_visibility(const char *pkgid, uid_t uid);
