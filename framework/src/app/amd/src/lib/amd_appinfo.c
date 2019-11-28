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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <glib.h>
#include <dirent.h>
#include <package-manager.h>
#include <pkgmgr-info.h>
#include <vconf.h>
#include <aul_sock.h>
#include <aul.h>
#include <cert-svc/ccert.h>
#include <cert-svc/cinstance.h>

#include "amd_util.h"
#include "amd_appinfo.h"
#include "amd_launch.h"
#include "amd_app_status.h"
#include "amd_signal.h"
#include "amd_app_property.h"
#include "amd_suspend.h"
#include "amd_login_monitor.h"
#include "amd_noti.h"

#define CATEGORY_IME "http://tizen.org/category/ime"

typedef int (*appinfo_handler_add_cb)(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data);
typedef void (*appinfo_handler_remove_cb)(void *data);

typedef struct _appinfo_vft {
	appinfo_handler_add_cb constructor;
	appinfo_handler_remove_cb destructor;
} appinfo_vft;

struct user_appinfo {
	uid_t uid;
	GHashTable *tbl; /* key is appid, value is struct appinfo */
};

struct app_event_info {
	int req_id;
	int type;
	uid_t uid;
};

struct pkg_event_info {
	uid_t target_uid;
	uid_t uid;
	const char *pkgid;
};

struct callback_info {
	appinfo_iter_callback cb;
	void *user_data;
};

static pkgmgr_client *pc;
static GHashTable *user_tbl;
static GHashTable *pkg_pending;
static GList *app_event_list;
static int gles = 1;

static void __free_appinfo_splash_image(gpointer data)
{
	struct appinfo_splash_image *splash_image = data;

	if (splash_image == NULL)
		return;

	if (splash_image->color_depth)
		free(splash_image->color_depth);
	if (splash_image->indicatordisplay)
		free(splash_image->indicatordisplay);
	if (splash_image->type)
		free(splash_image->type);
	if (splash_image->src)
		free(splash_image->src);
	free(splash_image);
}

static void __free_user_appinfo(gpointer data)
{
	struct user_appinfo *info = (struct user_appinfo *)data;

	g_hash_table_destroy(info->tbl);
	free(info);
}

static int __read_background_category(const char *category_name,
		void *user_data)
{
	struct appinfo *c = user_data;
	int category = (intptr_t)(c->val[AIT_BG_CATEGORY]);

	if (!category_name)
		return 0;

	if (strcmp(category_name, "disable") == 0) {
		c->val[AIT_BG_CATEGORY] = 0x00;
		return -1;
	}

	if (strcmp(category_name, "media") == 0) {
		c->val[AIT_BG_CATEGORY] = (char *)((intptr_t)(category |
				BACKGROUND_CATEGORY_MEDIA));
	} else if (strcmp(category_name, "download") == 0) {
		c->val[AIT_BG_CATEGORY] = (char *)((intptr_t)(category |
				BACKGROUND_CATEGORY_DOWNLOAD));
	} else if (strcmp(category_name, "background-network") == 0) {
		c->val[AIT_BG_CATEGORY] = (char *)((intptr_t)(category |
				BACKGROUND_CATEGORY_BACKGROUND_NETWORK));
	} else if (strcmp(category_name, "location") == 0) {
		c->val[AIT_BG_CATEGORY] = (char *)((intptr_t)(category |
				BACKGROUND_CATEGORY_LOCATION));
	} else if (strcmp(category_name, "sensor") == 0) {
		c->val[AIT_BG_CATEGORY] = (char *)((intptr_t)(category |
				BACKGROUND_CATEGORY_SENSOR));
	} else if (strcmp(category_name, "iot-communication") == 0) {
		c->val[AIT_BG_CATEGORY] = (char *)((intptr_t)(category |
				BACKGROUND_CATEGORY_IOT_COMMUNICATION));
	} else if (strcmp(category_name, "system") == 0) {
		c->val[AIT_BG_CATEGORY] = (char *)((intptr_t)(category |
				BACKGROUND_CATEGORY_SYSTEM));
	}

	return 0;
}

static void __appinfo_remove_splash_screen(void *data)
{
	struct appinfo_splash_screen *splash_screen =
		(struct appinfo_splash_screen *)data;

	if (splash_screen == NULL)
		return;

	if (splash_screen->portrait)
		g_hash_table_destroy(splash_screen->portrait);
	if (splash_screen->landscape)
		g_hash_table_destroy(splash_screen->landscape);
	free(splash_screen);
}

static int __appinfo_add_exec(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	char *exec = NULL;

	ret = pkgmgrinfo_appinfo_get_exec(handle, &exec);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get exec");
		return -1;
	}

	info->val[AIT_EXEC] = strdup(exec);
	if (info->val[AIT_EXEC] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_pkgtype(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	char *pkgtype = NULL;

	ret = pkgmgrinfo_appinfo_get_pkgtype(handle, &pkgtype);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get pkgtype");
		return -1;
	}

	info->val[AIT_PKGTYPE] = strdup(pkgtype);
	if (info->val[AIT_PKGTYPE] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_onboot(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	bool onboot = false;

	ret = pkgmgrinfo_appinfo_is_onboot(handle, &onboot);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get onboot");
		return -1;
	}

	info->val[AIT_ONBOOT] = strdup(onboot ? "true" : "false");
	if (info->val[AIT_ONBOOT] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_restart(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	bool restart = false;

	ret = pkgmgrinfo_appinfo_is_autorestart(handle, &restart);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get restart");
		return -1;
	}

	info->val[AIT_RESTART] = GINT_TO_POINTER(restart ? 1 : 0);

	return 0;
}

static int __appinfo_add_multi(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	bool multiple = false;

	ret = pkgmgrinfo_appinfo_is_multiple(handle, &multiple);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get multiple");
		return -1;
	}

	info->val[AIT_MULTI] = strdup(multiple ? "true" : "false");
	if (info->val[AIT_MULTI] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_hwacc(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	pkgmgrinfo_app_hwacceleration hwacc;

	ret = pkgmgrinfo_appinfo_get_hwacceleration(handle, &hwacc);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get hwacc");
		return -1;
	}

	info->val[AIT_HWACC] = strdup(
				(gles == 0 ||
				 hwacc == PMINFO_HWACCELERATION_OFF) ?
				"NOT_USE" :
				(hwacc == PMINFO_HWACCELERATION_ON) ?
				"USE" :
				"SYS");
	if (info->val[AIT_HWACC] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_perm(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	pkgmgrinfo_permission_type permission;

	ret = pkgmgrinfo_appinfo_get_permission_type(handle, &permission);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get permission type");
		return -1;
	}

	info->val[AIT_PERM] = strdup(
				(permission == PMINFO_PERMISSION_SIGNATURE) ?
				"signature" :
				(permission == PMINFO_PERMISSION_PRIVILEGE) ?
				"privilege" :
				"normal");
	if (info->val[AIT_PERM] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_pkgid(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	char *pkgid = NULL;

	ret = pkgmgrinfo_appinfo_get_pkgid(handle, &pkgid);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get pkgid");
		return -1;
	}

	info->val[AIT_PKGID] = strdup(pkgid);
	if (info->val[AIT_PKGID] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_preload(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	bool preload = false;

	ret = pkgmgrinfo_appinfo_is_preload(handle, &preload);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get preload");
		return -1;
	}

	info->val[AIT_PRELOAD] = strdup(preload ? "true" : "false");
	if (info->val[AIT_PRELOAD] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_status(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	info->val[AIT_STATUS] = strdup("installed");
	if (info->val[AIT_STATUS] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_pool(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	bool process_pool = false;

	ret = pkgmgrinfo_appinfo_is_process_pool(handle, &process_pool);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get process_pool");
		return -1;
	}

	info->val[AIT_POOL] = strdup(process_pool ? "true" : "false");
	if (info->val[AIT_POOL] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_comptype(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	char *component_type = NULL;

	ret = pkgmgrinfo_appinfo_get_component_type(handle, &component_type);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get component type");
		return -1;
	}

	info->val[AIT_COMPTYPE] = strdup(component_type);
	if (info->val[AIT_COMPTYPE] == NULL) {
		_E("Ouf ot memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_tep(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	char *tep_name = NULL;

	pkgmgrinfo_appinfo_get_tep_name(handle, &tep_name);
	if (tep_name && strlen(tep_name) > 0) {
		info->val[AIT_TEP] = strdup(tep_name);
		if (info->val[AIT_TEP] == NULL) {
			_E("Out of memory");
			return -1;
		}
	}

	return 0;
}

static int __appinfo_add_mountable_pkg(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	char *tpk_name = NULL;

	pkgmgrinfo_appinfo_get_zip_mount_file(handle, &tpk_name);
	if (tpk_name && strlen(tpk_name) > 0) {
		info->val[AIT_MOUNTABLE_PKG] = strdup(tpk_name);
		if (info->val[AIT_MOUNTABLE_PKG] == NULL) {
			_E("Out of memory");
			return -1;
		}
	}

	return 0;
}

static int __appinfo_add_storage_type(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	pkgmgrinfo_installed_storage installed_storage;

	ret = pkgmgrinfo_appinfo_get_installed_storage_location(handle,
			&installed_storage);
	if (ret == PMINFO_R_OK) {
		if (installed_storage == PMINFO_INTERNAL_STORAGE)
			info->val[AIT_STORAGE_TYPE] = strdup("internal");
		else if (installed_storage == PMINFO_EXTERNAL_STORAGE)
			info->val[AIT_STORAGE_TYPE] = strdup("external");
	} else {
		info->val[AIT_STORAGE_TYPE] = strdup("internal");
	}

	if (info->val[AIT_STORAGE_TYPE] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_bg_category(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;

	ret = pkgmgrinfo_appinfo_foreach_background_category(handle,
			__read_background_category, info);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get background category");
		return -1;
	}

	return 0;
}

static int __appinfo_add_launch_mode(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	char *mode = NULL;

	ret = pkgmgrinfo_appinfo_get_launch_mode(handle, &mode);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get launch_mode");
		return -1;
	}

	info->val[AIT_LAUNCH_MODE] = strdup(mode ? mode : "single");
	if (info->val[AIT_LAUNCH_MODE] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_global(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	bool is_global = false;

	ret = pkgmgrinfo_appinfo_is_global(handle, &is_global);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get is_global info");
		return -1;
	}

	info->val[AIT_GLOBAL] = strdup(is_global ? "true" : "false");
	if (info->val[AIT_GLOBAL] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_effective_appid(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	char *effective_appid = NULL;

	pkgmgrinfo_appinfo_get_effective_appid(handle, &effective_appid);
	if (effective_appid && strlen(effective_appid) > 0) {
		info->val[AIT_EFFECTIVE_APPID] = strdup(effective_appid);
		if (info->val[AIT_EFFECTIVE_APPID] == NULL) {
			_E("Out of memory");
			return -1;
		}
	}

	return 0;
}

static int __appinfo_add_taskmanage(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	bool taskmanage = false;

	ret = pkgmgrinfo_appinfo_is_taskmanage(handle, &taskmanage);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get taskmanage");
		return -1;
	}

	info->val[AIT_TASKMANAGE] = strdup(taskmanage ? "true" : "false");
	if (info->val[AIT_TASKMANAGE] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_apptype(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	char *apptype = NULL;

	ret = pkgmgrinfo_appinfo_get_apptype(handle, &apptype);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get apptype");
		return -1;
	}

	info->val[AIT_APPTYPE] = strdup(apptype);
	if (info->val[AIT_APPTYPE] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_root_path(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	char *path = NULL;

	ret = pkgmgrinfo_appinfo_get_root_path(handle, &path);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get root path");
		return -1;
	}

	if (path) {
		info->val[AIT_ROOT_PATH] = strdup(path);
		if (info->val[AIT_ROOT_PATH] == NULL) {
			_E("Out of memory");
			return -1;
		}
	}

	return 0;
}

static int __add_splash_screen_list_cb(const char *src, const char *type,
		const char *orientation, const char *indicatordisplay,
		const char *operation, const char *color_depth, void *user_data)
{
	struct appinfo *info = (struct appinfo *)user_data;
	struct appinfo_splash_screen *splash_screen;
	struct appinfo_splash_image *splash_image;
	char *key;

	splash_image = (struct appinfo_splash_image *)calloc(1,
			sizeof(struct appinfo_splash_image));
	if (splash_image == NULL) {
		_E("out of memory");
		return -1;
	}

	splash_image->src = strdup(src);
	if (splash_image->src == NULL) {
		_E("Out of memory");
		free(splash_image);
		return -1;
	}

	splash_image->type = strdup(type);
	if (splash_image->type == NULL) {
		_E("Out of memory");
		__free_appinfo_splash_image(splash_image);
		return -1;
	}

	splash_image->indicatordisplay = strdup(indicatordisplay);
	if (splash_image->indicatordisplay == NULL) {
		_E("Out of memory");
		__free_appinfo_splash_image(splash_image);
		return -1;
	}

	splash_image->color_depth = strdup(color_depth);
	if (splash_image->color_depth == NULL) {
		_E("Out of memory");
		__free_appinfo_splash_image(splash_image);
		return -1;
	}

	key = strdup(operation);
	if (key == NULL) {
		_E("Out of memory");
		__free_appinfo_splash_image(splash_image);
		return -1;
	}

	splash_screen = (struct appinfo_splash_screen *)
		info->val[AIT_SPLASH_SCREEN];
	if (splash_screen == NULL) {
		splash_screen = (struct appinfo_splash_screen *)calloc(1,
				sizeof(struct appinfo_splash_screen));
		if (splash_screen == NULL) {
			_E("out of memory");
			__free_appinfo_splash_image(splash_image);
			free(key);
			return -1;
		}
		info->val[AIT_SPLASH_SCREEN] = (char *)splash_screen;
	}

	if (strcasecmp(orientation, "portrait") == 0) {
		if (splash_screen->portrait == NULL) {
			splash_screen->portrait = g_hash_table_new_full(
					g_str_hash, g_str_equal, free,
					__free_appinfo_splash_image);
		}
		g_hash_table_insert(splash_screen->portrait, key, splash_image);
	} else if (strcasecmp(orientation, "landscape") == 0) {
		if (splash_screen->landscape == NULL) {
			splash_screen->landscape = g_hash_table_new_full(
					g_str_hash, g_str_equal, free,
					__free_appinfo_splash_image);
		}
		g_hash_table_insert(splash_screen->landscape, key,
				splash_image);
	} else {
		__free_appinfo_splash_image(splash_image);
		free(key);
	}

	return 0;
}

static int __appinfo_add_splash_screens(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;

	ret = pkgmgrinfo_appinfo_foreach_splash_screen(handle,
			__add_splash_screen_list_cb, info);
	if (ret < 0) {
		_E("Failed to get splash screen");
		return -1;
	}

	return 0;
}

static int __appinfo_add_splash_screen_display(
		const pkgmgrinfo_appinfo_h handle, struct appinfo *info,
		void *data)
{
	bool splash_screen_display = true;
	int ret;

	ret = pkgmgrinfo_appinfo_get_splash_screen_display(handle,
			&splash_screen_display);
	if (ret < 0)
		_D("Failed to get splash screen display");

	info->val[AIT_SPLASH_SCREEN_DISPLAY] =
		GINT_TO_POINTER(splash_screen_display ? 1 : 0);

	return 0;
}

static int __appinfo_add_api_version(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	char *api_version;

	ret = pkgmgrinfo_appinfo_get_api_version(handle, &api_version);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get api version");
		return -1;
	}

	info->val[AIT_API_VERSION] = strdup(api_version);
	if (info->val[AIT_API_VERSION] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_enablement(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	bool disabled = false;

	ret = pkgmgrinfo_appinfo_is_disabled(handle, &disabled);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get enablement");
		return -1;
	}

	info->val[AIT_ENABLEMENT] = GINT_TO_POINTER(disabled ? 0 : 1);

	return 0;
}

static int __appinfo_add_cooldown_mode(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	int support_mode = 0;

	ret = pkgmgrinfo_appinfo_get_support_mode(handle, &support_mode);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get support mode value");
		return -1;
	}

	if (support_mode & APP_SUPPORT_MODE_COOL_DOWN_VAL)
		info->val[AIT_COOLDOWN] = strdup("true");
	else
		info->val[AIT_COOLDOWN] = strdup("false");
	if (info->val[AIT_COOLDOWN] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_system(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	bool system = false;

	ret = pkgmgrinfo_appinfo_is_system(handle, &system);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get support mode value");
		return -1;
	}

	if (system)
		info->val[AIT_SYSTEM] = strdup("true");
	else
		info->val[AIT_SYSTEM] = strdup("false");
	if (info->val[AIT_SYSTEM] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static int __appinfo_add_ime(const pkgmgrinfo_appinfo_h handle,
		struct appinfo *info, void *data)
{
	int ret;
	bool exist = false;

	ret = pkgmgrinfo_appinfo_is_category_exist(handle, CATEGORY_IME,
			&exist);
	if (ret != PMINFO_R_OK) {
		_E("Failed to check ime category");
		return -1;
	}

	info->val[AIT_IME] = strdup(exist ? "true" : "false");
	if (info->val[AIT_IME] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

static  appinfo_vft appinfo_table[AIT_MAX] = {
	[AIT_NAME] = {
		.constructor = NULL,
		.destructor = NULL
	},
	[AIT_EXEC] = {
		.constructor = __appinfo_add_exec,
		.destructor = free
	},
	[AIT_PKGTYPE] = {
		.constructor = __appinfo_add_pkgtype,
		.destructor = free
	},
	[AIT_ONBOOT] = {
		.constructor = __appinfo_add_onboot,
		.destructor = free
	},
	[AIT_RESTART] = {
		.constructor = __appinfo_add_restart,
		.destructor = NULL
	},
	[AIT_MULTI] = {
		.constructor = __appinfo_add_multi,
		.destructor = free
	},
	[AIT_HWACC] = {
		.constructor = __appinfo_add_hwacc,
		.destructor = free
	},
	[AIT_PERM] = {
		.constructor = __appinfo_add_perm,
		.destructor = free
	},
	[AIT_PKGID] = {
		.constructor = __appinfo_add_pkgid,
		.destructor = free
	},
	[AIT_PRELOAD] = {
		.constructor = __appinfo_add_preload,
		.destructor = free
	},
	[AIT_STATUS] = {
		.constructor = __appinfo_add_status,
		.destructor = free
	},
	[AIT_POOL] = {
		.constructor = __appinfo_add_pool,
		.destructor = free
	},
	[AIT_COMPTYPE] = {
		.constructor = __appinfo_add_comptype,
		.destructor = free
	},
	[AIT_TEP] = {
		.constructor = __appinfo_add_tep,
		.destructor = free
	},
	[AIT_MOUNTABLE_PKG] = {
		.constructor = __appinfo_add_mountable_pkg,
		.destructor = free
	},
	[AIT_STORAGE_TYPE] = {
		.constructor = __appinfo_add_storage_type,
		.destructor = free
	},
	[AIT_BG_CATEGORY] = {
		.constructor = __appinfo_add_bg_category,
		.destructor = NULL
	},
	[AIT_LAUNCH_MODE] = {
		.constructor = __appinfo_add_launch_mode,
		.destructor = free
	},
	[AIT_GLOBAL] = {
		.constructor = __appinfo_add_global,
		.destructor = free
	},
	[AIT_EFFECTIVE_APPID] = {
		.constructor = __appinfo_add_effective_appid,
		.destructor = free
	},
	[AIT_TASKMANAGE] = {
		.constructor = __appinfo_add_taskmanage,
		.destructor = free
	},
	[AIT_VISIBILITY] = {
		.constructor = NULL,
		.destructor = free
	},
	[AIT_APPTYPE] = {
		.constructor = __appinfo_add_apptype,
		.destructor = free
	},
	[AIT_ROOT_PATH] = {
		.constructor = __appinfo_add_root_path,
		.destructor = free
	},
	[AIT_SPLASH_SCREEN] = {
		.constructor = __appinfo_add_splash_screens,
		.destructor = __appinfo_remove_splash_screen
	},
	[AIT_SPLASH_SCREEN_DISPLAY] = {
		.constructor = __appinfo_add_splash_screen_display,
		.destructor = NULL
	},
	[AIT_API_VERSION] = {
		.constructor = __appinfo_add_api_version,
		.destructor = free
	},
	[AIT_ENABLEMENT] = {
		.constructor = __appinfo_add_enablement,
		.destructor = NULL
	},
	[AIT_COOLDOWN] = {
		.constructor = __appinfo_add_cooldown_mode,
		.destructor = free
	},
	[AIT_SYSTEM] = {
		.constructor = __appinfo_add_system,
		.destructor = free
	},
	[AIT_IME] = {
		.constructor = __appinfo_add_ime,
		.destructor = free
	},
};

static void __appinfo_remove_handler(gpointer data)
{
	struct appinfo *c = data;
	int i;

	if (!c)
		return;

	for (i = AIT_START; i < AIT_MAX; i++) {
		if (appinfo_table[i].destructor && c->val[i] != NULL)
			appinfo_table[i].destructor(c->val[i]);
	}

	free(c);
}

static int __appinfo_insert_handler (const pkgmgrinfo_appinfo_h handle,
					void *data)
{
	int i;
	struct appinfo *c;
	struct user_appinfo *info = (struct user_appinfo *)data;
	char *appid;
	int ret;
	char err_buf[1024];

	if (!handle || !info) {
		_E("null app handle");
		return -1;
	}

	if (pkgmgrinfo_appinfo_get_appid(handle, &appid) != PMINFO_R_OK) {
		_E("fail to get appinfo");
		return -1;
	}

	g_hash_table_remove(info->tbl, appid);

	c = calloc(1, sizeof(struct appinfo));
	if (!c) {
		_E("create appinfo: %s",
				strerror_r(errno, err_buf, sizeof(err_buf)));
		return -1;
	}

	c->val[AIT_NAME] = strdup(appid);
	if (c->val[AIT_NAME] == NULL) {
		_E("Out of memory");
		free(c);
		return -1;
	}

	for (i = AIT_START; i < AIT_MAX; i++) {
		if (appinfo_table[i].constructor) {
			ret = appinfo_table[i].constructor(handle, c, info);
			if (ret < 0) {
				_E("failed to load appinfo of %s", appid);
				__appinfo_remove_handler(c);
				return 0;
			}
		}
	}

	SECURE_LOGD("%s : %s : %s : %s", c->val[AIT_NAME], c->val[AIT_COMPTYPE],
		c->val[AIT_PKGTYPE], c->val[AIT_APPTYPE]);

	g_hash_table_insert(info->tbl, c->val[AIT_NAME], c);
	_app_property_insert(info->uid, c->val[AIT_NAME], handle);

	return 0;
}

static int __appinfo_update_handler(const pkgmgrinfo_appinfo_h handle,
		void *data)
{
	int i;
	struct appinfo *c;
	struct user_appinfo *info = (struct user_appinfo *)data;
	char *appid;
	int ret;
	bool restart;
	int auto_restart;

	if (!handle || !info) {
		_E("Invalid parameter");
		return -1;
	}

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get appinfo");
		return -1;
	}

	c = (struct appinfo *)g_hash_table_lookup(info->tbl, appid);
	if (!c) {
		c = calloc(1, sizeof(struct appinfo));
		if (!c) {
			_E("Failed to create appinfo(%s)", appid);
			return -1;
		}

		c->val[AIT_NAME] = strdup(appid);
		if (c->val[AIT_NAME] == NULL) {
			_E("Out of memory");
			free(c);
			return -1;
		}

		g_hash_table_insert(info->tbl, c->val[AIT_NAME], c);
	}

	if (c->val[AIT_STATUS] && strcmp(c->val[AIT_STATUS], "restart") == 0)
		restart = true;
	else
		restart = false;

	_app_property_delete(info->uid, appid);
	for (i = AIT_START + 1; i < AIT_MAX; i++) {
		if (appinfo_table[i].destructor && c->val[i])
			appinfo_table[i].destructor(c->val[i]);
		c->val[i] = NULL;

		if (appinfo_table[i].constructor) {
			ret = appinfo_table[i].constructor(handle, c, info);
			if (ret < 0) {
				g_hash_table_remove(info->tbl, appid);
				return -1;
			}
		}
	}
	SECURE_LOGD("%s : %s : %s : %s",
			c->val[AIT_NAME], c->val[AIT_COMPTYPE],
			c->val[AIT_PKGTYPE], c->val[AIT_APPTYPE]);
	_app_property_insert(info->uid, appid, handle);

	auto_restart = GPOINTER_TO_INT(c->val[AIT_RESTART]);
	if (auto_restart && restart)
		_launch_start_app_local(info->uid, c->val[AIT_NAME]);
	else
		_launch_start_onboot_app_local(info->uid, c->val[AIT_NAME], c);

	return 0;
}

static int __insert_appinfo(const pkgmgrinfo_appinfo_h handle, void *data)
{
	int ret;
	struct appinfo *ai;
	struct user_appinfo *info = (struct user_appinfo *)data;
	char *appid = NULL;

	ret = __appinfo_insert_handler(handle, data);
	if (ret < 0)
		return -1;

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret != PMINFO_R_OK)
		return -1;

	ai = (struct appinfo *)g_hash_table_lookup(info->tbl, appid);
	if (ai == NULL)
		return -1;

	_launch_start_onboot_app_local(info->uid, appid, ai);

	return 0;
}

static void __remove_user_appinfo(uid_t uid)
{
	g_hash_table_remove(user_tbl, GINT_TO_POINTER(uid));
}

static struct user_appinfo *__add_user_appinfo(uid_t uid)
{
	int r;
	struct user_appinfo *info;

	info = calloc(1, sizeof(struct user_appinfo));
	if (info == NULL) {
		_E("out of memory");
		return NULL;
	}

	info->uid = uid;
	info->tbl = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			__appinfo_remove_handler);
	if (info->tbl == NULL) {
		_E("out of memory");
		free(info);
		return NULL;
	}

	g_hash_table_insert(user_tbl, GINT_TO_POINTER(uid), info);

	r = pkgmgrinfo_appinfo_get_usr_installed_list_full(
			__appinfo_insert_handler, uid,
			PMINFO_APPINFO_GET_SPLASH_SCREEN, info);
	if (r != PMINFO_R_OK) {
		__remove_user_appinfo(uid);
		return NULL;
	}

	_D("loaded appinfo table for uid %d", uid);

	return info;
}

static struct user_appinfo *__find_user_appinfo(uid_t uid)
{
	return g_hash_table_lookup(user_tbl, GINT_TO_POINTER(uid));
}

static void __appinfo_set_blocking_cb(void *user_data,
		const char *appid, struct appinfo *info)
{
	struct pkg_event_info *pkg_info = (struct pkg_event_info *)user_data;

	if (strcmp(info->val[AIT_PKGID], pkg_info->pkgid))
		return;

	if (pkg_info->target_uid == GLOBAL_USER &&
			!strcmp(info->val[AIT_GLOBAL], "false"))
		return;
	else if (pkg_info->target_uid != GLOBAL_USER &&
			!strcmp(info->val[AIT_GLOBAL], "true"))
		return;

	free(info->val[AIT_STATUS]);
	info->val[AIT_STATUS] = strdup("blocking");
	_D("%s status changed: blocking", appid);
}

static void __appinfo_unset_blocking_cb(void *user_data,
		const char *appid, struct appinfo *info)
{
	struct pkg_event_info *pkg_info = (struct pkg_event_info *)user_data;

	if (strcmp(info->val[AIT_PKGID], pkg_info->pkgid))
		return;

	if (pkg_info->target_uid == GLOBAL_USER &&
			!strcmp(info->val[AIT_GLOBAL], "false"))
		return;
	else if (pkg_info->target_uid != GLOBAL_USER &&
			!strcmp(info->val[AIT_GLOBAL], "true"))
		return;

	free(info->val[AIT_STATUS]);
	info->val[AIT_STATUS] = strdup("installed");
	if (info->val[AIT_STATUS] == NULL)
		_W("Out of memory");
	_D("%s status changed: installed", appid);
}

static void __appinfo_restart_cb(void *user_data,
		const char *appid, struct appinfo *info)
{
	bool restart;
	int auto_restart;
	struct pkg_event_info *pkg_info = (struct pkg_event_info *)user_data;

	if (strcmp(info->val[AIT_PKGID], pkg_info->pkgid))
		return;

	if (info->val[AIT_STATUS] && !strcmp(info->val[AIT_STATUS], "restart"))
		restart = true;
	else
		restart = false;

	__appinfo_unset_blocking_cb(user_data, appid, info);

	auto_restart = GPOINTER_TO_INT(info->val[AIT_RESTART]);
	if (auto_restart && restart)
		_launch_start_app_local(pkg_info->uid, info->val[AIT_NAME]);
}

static gboolean __appinfo_remove_cb(gpointer key, gpointer value, gpointer data)
{
	struct pkg_event_info *pkg_info = (struct pkg_event_info *)data;
	struct appinfo *info = (struct appinfo *)value;

	if (strcmp(info->val[AIT_PKGID], pkg_info->pkgid))
		return FALSE;

	if (pkg_info->target_uid == GLOBAL_USER &&
			!strcmp(info->val[AIT_GLOBAL], "false"))
		return FALSE;
	else if (pkg_info->target_uid != GLOBAL_USER &&
			!strcmp(info->val[AIT_GLOBAL], "true"))
		return FALSE;

	_app_property_delete(GPOINTER_TO_UINT(key), info->val[AIT_NAME]);

	_D("appinfo removed: %s", info->val[AIT_NAME]);
	return TRUE;
}

static void __appinfo_delete_on_event(uid_t uid, void *data)
{
	struct user_appinfo *info;

	info = __find_user_appinfo(uid);
	if (info == NULL) {
		_E("cannot find appinfo for uid %d", uid);
		return;
	}

	g_hash_table_foreach_remove(info->tbl, __appinfo_remove_cb,
			(gpointer)data);
}

static void __appinfo_insert_on_event(uid_t uid, const char *pkgid)
{
	_appinfo_insert(uid, pkgid);
}

static void __appinfo_update_on_event(uid_t uid, void *data)
{
	struct pkg_event_info *pkg_info = (struct pkg_event_info *)data;
	struct user_appinfo *info;
	pkgmgrinfo_pkginfo_h handle;
	int ret;

	info = __find_user_appinfo(uid);
	if (info == NULL) {
		_E("cannot find appinfo for uid %d", uid);
		return;
	}

	ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkg_info->pkgid, uid, &handle);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get pkginfo(%s)", pkg_info->pkgid);
		return;
	}

	ret = pkgmgrinfo_appinfo_get_usr_list(handle, PMINFO_ALL_APP,
			__appinfo_update_handler, info, info->uid);
	if (ret != PMINFO_R_OK) {
		_E("Failed to update pkginfo(%s)", pkg_info->pkgid);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return;
	}

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
}

static void __set_blocking(struct pkg_event_info *info)
{
	uid_t *uids = NULL;
	int r;
	int i;

	if (info->target_uid < REGULAR_UID_MIN) {
		r = _login_monitor_get_uids(&uids);
		if (r <= 0)
			return;

		for (i = 0; i < r; i++) {
			_appinfo_foreach(uids[i],
					__appinfo_set_blocking_cb, info);
			_D("terminate apps by PackageID - %s", info->pkgid);
			_app_status_terminate_apps_by_pkgid(info->pkgid,
					uids[i]);
		}
		free(uids);

		return;
	}

	_appinfo_foreach(info->target_uid, __appinfo_set_blocking_cb, info);
	_D("terminate apps by PackageID - %s", info->pkgid);
	_app_status_terminate_apps_by_pkgid(info->pkgid, info->target_uid);
}

static void __unset_blocking(struct pkg_event_info *info, bool restart)
{
	uid_t *uids = NULL;
	int r;
	int i;

	if (info->target_uid < REGULAR_UID_MIN) {
		r = _login_monitor_get_uids(&uids);
		if (r <= 0)
			return;

		for (i = 0; i < r; i++) {
			if (restart) {
				info->uid = uids[i];
				_appinfo_foreach(uids[i],
						__appinfo_restart_cb, info);
			} else {
				_appinfo_foreach(uids[i],
						__appinfo_unset_blocking_cb,
						info);
			}
		}
		free(uids);

		return;
	}

	if (restart) {
		info->uid = info->target_uid;
		_appinfo_foreach(info->target_uid,
				__appinfo_restart_cb, info);
	} else {
		_appinfo_foreach(info->target_uid,
				__appinfo_unset_blocking_cb, info);
	}
}

static void __delete_on_event(struct pkg_event_info *info)
{
	uid_t *uids = NULL;
	int r;
	int i;

	if (info->target_uid < REGULAR_UID_MIN) {
		r = _login_monitor_get_uids(&uids);
		if (r <= 0)
			return;

		for (i = 0; i < r; i++)
			__appinfo_delete_on_event(uids[i], info);
		free(uids);

		return;
	}

	__appinfo_delete_on_event(info->target_uid, info);
}

static void __insert_on_event(struct pkg_event_info *info)
{
	uid_t *uids = NULL;
	int r;
	int i;

	if (info->target_uid < REGULAR_UID_MIN) {
		r = _login_monitor_get_uids(&uids);
		if (r <= 0)
			return;

		for (i = 0; i < r; i++)
			__appinfo_insert_on_event(uids[i], info->pkgid);
		free(uids);

		return;
	}

	__appinfo_insert_on_event(info->target_uid, info->pkgid);
}

static void __update_on_event(struct pkg_event_info *info)
{
	uid_t *uids = NULL;
	int r;
	int i;

	if (info->target_uid < REGULAR_UID_MIN) {
		r = _login_monitor_get_uids(&uids);
		if (r <= 0)
			return;

		for (i = 0; i < r; i++)
			__appinfo_update_on_event(uids[i], info);
		free(uids);

		return;
	}

	__appinfo_update_on_event(info->target_uid, info);
}

static int __appinfo_is_pkg_exist(uid_t uid, const char *pkgid)
{
	int r;
	struct user_appinfo *info;
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	uid_t *uids = NULL;
	struct appinfo *ai;

	if (pkgid == NULL)
		return 0;

	if (uid < REGULAR_UID_MIN) {
		r = _login_monitor_get_uids(&uids);
		if (r <= 0)
			return 0;

		uid = uids[0];

		free(uids);
	}

	info = __find_user_appinfo(uid);
	if (info == NULL) {
		_E("cannot find appinfo for uid %d", uid);
		return 0;
	}

	g_hash_table_iter_init(&iter, info->tbl);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		ai = (struct appinfo *)value;
		if (strcmp(pkgid, ai->val[AIT_PKGID]) == 0)
			return 1;
	}

	return 0;
}

static void __appinfo_enable_pkg_apps(uid_t uid, const char *pkgid, int enable)
{
	int r;
	int i;
	struct user_appinfo *info;
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	uid_t *uids = NULL;
	struct appinfo *ai;
	int prev_val;
	const char *appid;

	if (pkgid == NULL)
		return;

	if (uid < REGULAR_UID_MIN) {
		r = _login_monitor_get_uids(&uids);
		if (r <= 0)
			return;

		for (i = 0; i < r; i++)
			__appinfo_enable_pkg_apps(uids[i], pkgid, enable);

		free(uids);

		return;
	}

	info = __find_user_appinfo(uid);
	if (info == NULL) {
		_E("cannot find appinfo for uid %d", uid);
		return;
	}

	g_hash_table_iter_init(&iter, info->tbl);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		ai = (struct appinfo *)value;
		if (strcmp(pkgid, ai->val[AIT_PKGID]) == 0) {
			_appinfo_get_int_value(ai, AIT_ENABLEMENT, &prev_val);
			_appinfo_set_int_value(ai, AIT_ENABLEMENT, enable);
			if (prev_val == 0 && enable == 1) {
				appid = _appinfo_get_value(ai, AIT_NAME);
				_launch_start_onboot_app_local(uid, appid, ai);
			}
		}
	}
}

static int __package_event_cb(uid_t target_uid, int req_id,
		const char *pkg_type, const char *pkgid,
		const char *key, const char *val, const void *pmsg, void *data)
{
	int ret;
	char *op;
	struct pkg_event_info info = {
		.target_uid = target_uid,
		.pkgid = pkgid
	};
	pkgmgrinfo_pkginfo_h pkginfo;

	if (!strcasecmp(key, "start")) {
		if (!strcasecmp(val, "uninstall") ||
				!strcasecmp(val, "update") ||
				!strcasecmp(val, "move")) {
			_W("[__PKGMGR__] Package(%s) event(%s) - start",
					pkgid, val);
			__set_blocking(&info);
		}

		g_hash_table_insert(pkg_pending, strdup(pkgid), strdup(val));
	}

	if (!strcasecmp(key, "error")) {
		op = g_hash_table_lookup(pkg_pending, pkgid);
		if (op == NULL)
			return 0;

		if (!strcasecmp(op, "uninstall") ||
				!strcasecmp(op, "update") ||
				!strcasecmp(op, "move")) {
			_W("[__PKGMGR__] Package(%s) event(%s) - error",
					pkgid, val);
			__unset_blocking(&info, true);
			_noti_send("appinfo.package.update.error",
					target_uid, 0, (void *)pkgid, NULL);
		}

		g_hash_table_remove(pkg_pending, pkgid);
	}

	if (!strcasecmp(key, "end")) {
		_W("[__PKGMGR__] Package(%s) event(%s) - end", pkgid, val);
		op = g_hash_table_lookup(pkg_pending, pkgid);
		if (op == NULL)
			return 0;

		if (!strcasecmp(op, "uninstall")) {
			ret = pkgmgrinfo_pkginfo_get_usr_disabled_pkginfo(
					info.pkgid, info.target_uid,
					&pkginfo);
			if (ret == PMINFO_R_OK) {
				pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo);
				__unset_blocking(&info, false);
				__appinfo_enable_pkg_apps(info.target_uid,
						info.pkgid, 0);
			} else {
				__delete_on_event(&info);
			}
			_noti_send("appinfo.package.uninstall.end",
					target_uid, 0, (void *)pkgid, NULL);
		} else if (!strcasecmp(op, "install")) {
			if (!__appinfo_is_pkg_exist(
					info.target_uid,
					info.pkgid)) {
				__insert_on_event(&info);
			} else {
				__unset_blocking(&info, false);
				__appinfo_enable_pkg_apps(info.target_uid,
						info.pkgid, 1);
			}
			_noti_send("appinfo.package.install.end",
					target_uid, 0, (void *)pkgid, NULL);
		} else if (!strcasecmp(op, "update") ||
				!strcasecmp(op, "move")) {
			__update_on_event(&info);
			_noti_send("appinfo.package.update.end",
					target_uid, 0, (void *)pkgid, NULL);
		}

		g_hash_table_remove(pkg_pending, pkgid);
	}

	return 0;
}

static void __add_app_event_info(int req_id, int type, uid_t uid)
{
	struct app_event_info *info;

	info = (struct app_event_info *)malloc(sizeof(struct app_event_info));
	if (info == NULL) {
		_E("Out of memory");
		return;
	}

	info->req_id = req_id;
	info->type = type;
	info->uid = uid;

	app_event_list = g_list_append(app_event_list, (gpointer)info);
}

static struct app_event_info *__find_app_event_info(int req_id, uid_t uid)
{
	GList *iter;
	struct app_event_info *info;

	iter = g_list_first(app_event_list);
	while (iter) {
		info = (struct app_event_info *)iter->data;
		if (info && info->req_id == req_id && info->uid == uid)
			return info;

		iter = g_list_next(iter);
	}

	return NULL;
}

static void __remove_app_event_info(struct app_event_info *info)
{
	if (info == NULL)
		return;

	app_event_list = g_list_remove(app_event_list, info);
	free(info);
}

static void __handle_app_event_start(const char *event_name,
		struct appinfo *ai, const char *appid, int req_id, uid_t uid)
{
	int old = 0;

	if (!strcasecmp(event_name, "enable_global_app_for_uid") ||
			!strcasecmp(event_name, "enable_app")) {
		if (ai) {
			_appinfo_get_int_value(ai, AIT_ENABLEMENT, &old);
			old |= APP_ENABLEMENT_MASK_REQUEST;
			_appinfo_set_int_value(ai, AIT_ENABLEMENT, old);
		}
		__add_app_event_info(req_id, AIT_ENABLEMENT, uid);
	} else if (!strcasecmp(event_name, "disable_global_app_for_uid") ||
			!strcasecmp(event_name, "disable_app")) {
		__add_app_event_info(req_id, AIT_ENABLEMENT, uid);
	} else if (!strcasecmp(event_name, "enable_app_splash_screen")) {
		if (ai) {
			_appinfo_get_int_value(ai, AIT_SPLASH_SCREEN_DISPLAY,
					&old);
			old |= APP_ENABLEMENT_MASK_REQUEST;
			_appinfo_set_int_value(ai, AIT_SPLASH_SCREEN_DISPLAY,
					old);
		}
		__add_app_event_info(req_id, AIT_SPLASH_SCREEN_DISPLAY, uid);
	} else if (!strcasecmp(event_name, "disable_app_splash_screen")) {
		__add_app_event_info(req_id, AIT_SPLASH_SCREEN_DISPLAY, uid);
	}
}

static void __handle_app_event_end(const char *event_name,
		struct appinfo *ai, const char *appid, int req_id, uid_t uid)
{
	pkgmgrinfo_appinfo_h handle;
	struct user_appinfo *info;
	struct app_event_info *ei;
	int old = 0;
	int r;

	ei = __find_app_event_info(req_id, uid);
	if (ei == NULL)
		return;

	if (!strcasecmp(event_name, "ok")) {
		if (ei->type == AIT_ENABLEMENT) {
			if (ai) {
				_appinfo_get_int_value(ai, ei->type, &old);
				old >>= 1;
				_appinfo_set_int_value(ai, ei->type, old);
			} else {
				info = __find_user_appinfo(uid);
				if (info == NULL) {
					_E("Failed to load appinfo(%d)", uid);
					__remove_app_event_info(ei);
					return;
				}

				r = pkgmgrinfo_appinfo_get_usr_appinfo(appid,
						uid, &handle);
				if (r != PMINFO_R_OK) {
					_E("Failed to get appinfo(%s)", appid);
					__remove_app_event_info(ei);
					return;
				}

				_I("add the new appinfo(%s)", appid);
				__insert_appinfo(handle, info);
				pkgmgrinfo_appinfo_destroy_appinfo(handle);
				__remove_app_event_info(ei);
				_noti_send("appinfo.app.enabled.end",
						uid, 0, (void *)appid, NULL);
				return;
			}

			if (!(old & APP_ENABLEMENT_MASK_ACTIVE)) {
				_E("terminate apps: %s(%d)", appid, uid);
				_app_status_terminate_apps(appid, uid);
				_noti_send("appinfo.app.disabled.end",
						uid, 0, (void *)appid, NULL);
			} else if (old & APP_ENABLEMENT_MASK_ACTIVE) {
				_launch_start_onboot_app_local(uid, appid, ai);
				_noti_send("appinfo.app.enabled.end",
						uid, 0, (void *)appid, NULL);
			}
		} else if (ei->type == AIT_SPLASH_SCREEN_DISPLAY) {
			if (ai) {
				_appinfo_get_int_value(ai, ei->type, &old);
				old >>= 1;
				_appinfo_set_int_value(ai, ei->type, old);
			}
		}
	} else if (!strcasecmp(event_name, "fail")) {
		if (ei->type == AIT_ENABLEMENT ||
				ei->type == AIT_SPLASH_SCREEN_DISPLAY) {
			if (ai) {
				_appinfo_get_int_value(ai, ei->type, &old);
				old &= APP_ENABLEMENT_MASK_ACTIVE;
				_appinfo_set_int_value(ai, ei->type, old);
			}
		}
	}
	__remove_app_event_info(ei);
}

static int __package_app_event_cb(uid_t target_uid, int req_id,
		const char *pkg_type, const char *pkgid, const char *appid,
		const char *key, const char *val, const void *pmsg, void *data)
{
	struct appinfo *ai;
	uid_t *uids = NULL;
	int r;
	int i;

	_D("appid:%s, key:%s, val:%s, req_id: %d, target_uid: %d",
			appid, key, val, req_id, target_uid);
	if (target_uid < REGULAR_UID_MIN) {
		r = _login_monitor_get_uids(&uids);
		if (r <= 0)
			return 0;
	} else {
		r = 1;
	}

	for (i = 0; i < r; i++) {
		if (uids)
			target_uid = uids[i];
		ai = _appinfo_find(target_uid, appid);

		if (!strcasecmp(key, "start")) {
			__handle_app_event_start(val, ai, appid, req_id,
					target_uid);
		} else if (!strcasecmp(key, "end")) {
			__handle_app_event_end(val, ai, appid, req_id,
					target_uid);
		}
	}

	free(uids);
	return 0;
}

static int __init_package_event_handler(void *data)
{
	int ret;

	pc = pkgmgr_client_new(PC_LISTENING);
	if (pc == NULL)
		return -1;

	ret = pkgmgr_client_set_status_type(pc, PKGMGR_CLIENT_STATUS_ALL);
	if (ret < 0)
		return -1;

	ret = pkgmgr_client_listen_status(pc, __package_event_cb, NULL);
	if (ret < 0)
		return -1;

	ret = pkgmgr_client_listen_app_status(pc, __package_app_event_cb, NULL);
	if (ret < 0)
		return -1;

	_W("[__PKGMGR__] Package event handler is initialized");
	return 0;
}

static void __fini_package_event_handler(void)
{
	pkgmgr_client_free(pc);
}

static void __reload_appinfo(gpointer key, gpointer value, gpointer user_data)
{
	int r;
	struct user_appinfo *info = (struct user_appinfo *)value;

	g_hash_table_remove_all(info->tbl);

	r = pkgmgrinfo_appinfo_get_usr_installed_list_full(
			__appinfo_insert_handler, info->uid,
			PMINFO_APPINFO_GET_SPLASH_SCREEN, info);
	if (r != PMINFO_R_OK) {
		__remove_user_appinfo(info->uid);
		return;
	}

	_noti_send("appinfo.reload", (int)info->uid, 0, NULL, NULL);
	_D("reloaded appinfo table for uid %d", info->uid);
}

static int __dispatch_amd_reload_appinfo(request_h req)
{
	_D("AMD_RELOAD_APPINFO");
	g_hash_table_foreach(user_tbl, __reload_appinfo, NULL);
	_request_send_result(req, 0);

	return 0;
}

static request_cmd_dispatch __dispatch_table[] = {
	{
		.cmd = AMD_RELOAD_APPINFO,
		.callback = __dispatch_amd_reload_appinfo
	},
};

int _appinfo_init(void)
{
	FILE *fp;
	char buf[LINE_MAX];
	char *tmp;
	int r;

	fp = fopen("/proc/cmdline", "r");
	if (fp == NULL) {
		_E("appinfo init failed: %d", errno);
		return -1;
	}

	if (fgets(buf, sizeof(buf), fp) != NULL) {
		tmp = strstr(buf, "gles");
		if (tmp != NULL) {
			if (sscanf(tmp, "gles=%d", &gles) != 1)
				_D("Failed to convert format");
		}
	}
	fclose(fp);

	user_tbl = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
			__free_user_appinfo);
	if (user_tbl == NULL)
		return -1;

	pkg_pending = g_hash_table_new_full(g_str_hash, g_str_equal,
			free, free);
	if (pkg_pending == NULL)
		return -1;

	if (__init_package_event_handler(NULL) < 0)
		_signal_add_initializer(__init_package_event_handler, NULL);

	r = _request_register_cmds(__dispatch_table,
			ARRAY_SIZE(__dispatch_table));
	if (r < 0) {
		_E("Failed to register cmds");
		return -1;
	}

	return 0;
}

void _appinfo_fini(void)
{
	__fini_package_event_handler();
	g_hash_table_destroy(user_tbl);
	g_hash_table_destroy(pkg_pending);
}

struct appinfo *_appinfo_find(uid_t caller_uid, const char *appid)
{
	struct user_appinfo *info;

	if (appid == NULL) {
		_W("appid is NULL");
		return NULL;
	}

	/* search from user table */
	info = __find_user_appinfo(caller_uid);
	if (info == NULL)
		return NULL;

	return g_hash_table_lookup(info->tbl, appid);
}

int _appinfo_insert(uid_t uid, const char *pkgid)
{
	int ret;
	struct user_appinfo *info;
	pkgmgrinfo_pkginfo_h handle;

	info = __find_user_appinfo(uid);
	if (info == NULL) {
		_E("load appinfo for uid %d failed", uid);
		return -1;
	}

	ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle);
	if (ret != PMINFO_R_OK) {
		_E("get pkginfo failed: %s", pkgid);
		return -1;
	}

	ret = pkgmgrinfo_appinfo_get_usr_list(handle, PMINFO_ALL_APP,
			__insert_appinfo, info, info->uid);
	if (ret != PMINFO_R_OK) {
		_E("add appinfo of pkg %s failed", pkgid);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return -1;
	}

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return 0;
}

const char *_appinfo_get_value(const struct appinfo *c, enum appinfo_type type)
{
	if (!c) {
		_E("Invalid parameter");
		return NULL;
	}

	if (type < AIT_START || type >= AIT_MAX)
		return NULL;

	return c->val[type];
}

const void *_appinfo_get_ptr_value(const struct appinfo *c,
		enum appinfo_type type)
{
	if (!c) {
		_E("Invalid parameter");
		return NULL;
	}

	if (type < AIT_START || type >= AIT_MAX)
		return NULL;

	return c->val[type];
}

int _appinfo_get_int_value(const struct appinfo *c, enum appinfo_type type,
		int *val)
{
	if (!c) {
		_E("Invalid parameter");
		return -1;
	}

	if (type < AIT_START || type >= AIT_MAX)
		return -1;

	*val = GPOINTER_TO_INT(c->val[type]);

	return 0;
}

int _appinfo_get_boolean(const struct appinfo *c, enum appinfo_type type,
			bool *val)
{
	if (!c || type < AIT_START || type >= AIT_MAX || c->val[type] == NULL) {
		_E("Invalid parameter");
		return -1;
	}

	if (!strcmp(c->val[type], "true") || !strcmp(c->val[type], "1")) {
		*val = true;
	} else if (!strcmp(c->val[type], "false") ||
		!strcmp(c->val[type], "0")) {
		*val = false;
	} else {
		_E("Unexpected appinfo field value");
		return -1;
	}

	return 0;
}

int _appinfo_set_value(struct appinfo *c, enum appinfo_type type,
		const char *val)
{
	if (!c || !val) {
		_E("Invalid parameter");
		return -1;
	}

	if (type < AIT_START || type >= AIT_MAX)
		return -1;

	_D("%s : %s : %s", c->val[AIT_NAME], c->val[type], val);
	if (c->val[type])
		free(c->val[type]);

	c->val[type] = strdup(val);
	if (c->val[type] == NULL) {
		_E("Out of memory");
		return -1;
	}

	return 0;
}

int _appinfo_set_ptr_value(struct appinfo *c, enum appinfo_type type, void *val)
{
	if (!c || !val) {
		_E("Invalid parameter");
		return -1;
	}

	if (type < AIT_START || type >= AIT_MAX)
		return -1;

	_D("%s : %p : %p", c->val[AIT_NAME], c->val[type], val);
	if (appinfo_table[type].destructor && c->val[type] != NULL)
		appinfo_table[type].destructor(c->val[type]);

	c->val[type] = (char *)val;
	return 0;
}

int _appinfo_set_int_value(struct appinfo *c, enum appinfo_type type, int val)
{
	if (!c) {
		_E("Invalid parameter");
		return -1;
	}

	if (type < AIT_START || type >= AIT_MAX)
		return -1;

	_D("%s : %p : %d", c->val[AIT_NAME], c->val[type], val);

	c->val[type] = (char *)GINT_TO_POINTER(val);
	return 0;
}

static void __iter_cb(gpointer key, gpointer value, gpointer user_data)
{
	struct callback_info *cb_info = user_data;

	if (cb_info == NULL)
		return;

	cb_info->cb(cb_info->user_data, key, value);
}

void _appinfo_foreach(uid_t uid, appinfo_iter_callback cb, void *user_data)
{
	struct user_appinfo *info;
	struct callback_info cb_info = {
		.cb = cb,
		.user_data = user_data
	};

	if (!cb) {
		_E("Invalid parameter");
		return;
	}

	info = __find_user_appinfo(uid);
	if (info == NULL)
		return;

	g_hash_table_foreach(info->tbl, __iter_cb, &cb_info);
}

int _appinfo_load(uid_t uid)
{
	struct user_appinfo *info;

	info = __find_user_appinfo(uid);
	if (info) {
		_D("%d appinfo already exists", uid);
		return 0;
	}

	info = __add_user_appinfo(uid);
	if (info == NULL) {
		_W("Failed to load appinfo - %d", uid);
		return -1;
	}

	_noti_send("appinfo.load", (int)uid, 0, NULL, NULL);
	_D("loaded appinfo table for uid(%d)", uid);
	return 0;
}

void _appinfo_unload(uid_t uid)
{
	struct user_appinfo *info;

	info = __find_user_appinfo(uid);
	if (info == NULL) {
		_D("%d appinfo doesn't exist", uid);
		return;
	}

	__remove_user_appinfo(uid);
	_noti_send("appinfo.unload", (int)uid, 0, NULL, NULL);
	_D("unloaded appinfo table for uid(%d)", uid);
}

struct appinfo_splash_image *_appinfo_find_splash_image(struct appinfo *c,
		const char *name, bool landscape)
{
	struct appinfo_splash_screen *splash_screen;

	if (!c || !name) {
		_E("Invalid parameter");
		return NULL;
	}

	splash_screen = (struct appinfo_splash_screen *)_appinfo_get_value(c,
			AIT_SPLASH_SCREEN);
	if (!splash_screen)
		return NULL;

	if (landscape)
		return g_hash_table_lookup(splash_screen->landscape, name);

	return g_hash_table_lookup(splash_screen->portrait, name);
}

const char *_appinfo_splash_image_get_source(struct appinfo_splash_image *s)
{
	if (!s) {
		_E("Invalid parameter");
		return NULL;
	}

	return s->src;
}

const char *_appinfo_splash_image_get_type(struct appinfo_splash_image *s)
{
	if (!s) {
		_E("Invalid paramter");
		return NULL;
	}

	return s->type;
}

int _appinfo_splash_image_get_indicator_display(struct appinfo_splash_image *s)
{
	if (!s) {
		_E("Invalid parameter");
		return -1;
	}

	if (!strcmp(s->indicatordisplay, "true"))
		return 1;

	return 0;
}

int _appinfo_splash_image_get_color_depth(struct appinfo_splash_image *s)
{
	int color_depth = 24; /* default */

	if (!s) {
		_E("Invalid parameter");
		return -1;
	}

	if (isdigit(s->color_depth[0]))
		color_depth = atoi(s->color_depth);

	return color_depth;
}

bool _appinfo_is_pkg_updating(const char *pkgid)
{
	char *op;

	if (pkg_pending == NULL)
		return false;

	op = g_hash_table_lookup(pkg_pending, pkgid);
	if (op != NULL && !strcasecmp(op, "update"))
		return true;

	return false;
}

static char *__get_cert_value_from_pkginfo(const char *pkgid, uid_t uid)
{
	int ret;
	const char *cert_value;
	char *ret_cert;
	pkgmgrinfo_certinfo_h certinfo;

	ret = pkgmgrinfo_pkginfo_create_certinfo(&certinfo);
	if (ret != PMINFO_R_OK) {
		_E("Failed to create certinfo");
		return NULL;
	}

	ret = pkgmgrinfo_pkginfo_load_certinfo(pkgid, certinfo, uid);
	if (ret != PMINFO_R_OK) {
		_E("Failed to load certinfo");
		pkgmgrinfo_pkginfo_destroy_certinfo(certinfo);
		return NULL;
	}

	ret = pkgmgrinfo_pkginfo_get_cert_value(certinfo,
			PMINFO_DISTRIBUTOR_ROOT_CERT, &cert_value);
	if (ret != PMINFO_R_OK || cert_value == NULL) {
		_E("Failed to get cert value");
		pkgmgrinfo_pkginfo_destroy_certinfo(certinfo);
		return NULL;
	}

	ret_cert = strdup(cert_value);
	pkgmgrinfo_pkginfo_destroy_certinfo(certinfo);

	return ret_cert;
}

static int __get_visibility_from_certsvc(const char *cert_value)
{
	int ret;
	CertSvcInstance instance;
	CertSvcCertificate certificate;
	CertSvcVisibility visibility = CERTSVC_VISIBILITY_PUBLIC;

	if (cert_value == NULL)
		return (int)visibility;

	ret = certsvc_instance_new(&instance);
	if (ret != CERTSVC_SUCCESS) {
		_E("certsvc_instance_new() is failed.");
		return (int)visibility;
	}

	ret = certsvc_certificate_new_from_memory(instance,
			(const unsigned char *)cert_value,
			strlen(cert_value),
			CERTSVC_FORM_DER_BASE64,
			&certificate);
	if (ret != CERTSVC_SUCCESS) {
		_E("certsvc_certificate_new_from_memory() is failed.");
		certsvc_instance_free(instance);
		return (int)visibility;
	}

	ret = certsvc_certificate_get_visibility(certificate, &visibility);
	if (ret != CERTSVC_SUCCESS)
		_E("certsvc_certificate_get_visibility() is failed.");

	certsvc_certificate_free(certificate);
	certsvc_instance_free(instance);

	return (int)visibility;
}

int _appinfo_get_cert_visibility(const char *pkgid, uid_t uid)
{
	char *cert_value;
	int r;

	cert_value = __get_cert_value_from_pkginfo(pkgid, uid);
	r = __get_visibility_from_certsvc(cert_value);

	if (cert_value)
		free(cert_value);

	return r;
}
