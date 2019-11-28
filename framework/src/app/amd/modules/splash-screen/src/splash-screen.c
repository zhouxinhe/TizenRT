/*
 * Copyright (c) 2016 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <stdbool.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <glib.h>
#include <aul.h>
#include <aul_cmd.h>
#include <aul_svc.h>
#include <aul_svc_priv_key.h>
#include <wayland-client.h>
#include <wayland-tbm-client.h>
#include <tizen-launch-client-protocol.h>
#include <vconf.h>
#include <sensor_internal.h>
#include <amd.h>

#include "splash-screen-private.h"

#define APP_CONTROL_OPERATION_MAIN "http://tizen.org/appcontrol/operation/main"
#define K_FAKE_EFFECT			"__FAKE_EFFECT__"
#define SPLASH_SCREEN_INFO_PATH		"/usr/share/aul"
#define TAG_SPLASH_IMAGE		"[SplashImage]"
#define TAG_NAME			"Name"
#define TAG_FILE			"File"
#define TAG_TYPE			"Type"
#define TAG_ORIENTATION			"Orientation"
#define TAG_INDICATOR_DISPLAY		"Indicator-display"
#define TAG_COLOR_DEPTH			"Color-depth"
#define TIMEOUT_INTERVAL		10000 /* 10 sec */

#define TIZEN_FEATURE_CHARGER_STATUS \
	(amd_config_get_tizen_profile() & (AMD_TIZEN_PROFILE_WEARABLE))
#define TIZEN_FEATURE_AUTO_ROTATION \
	(!(amd_config_get_tizen_profile() & (AMD_TIZEN_PROFILE_TV)))

struct splash_image_s {
	struct tizen_launch_splash *image;
	char *appid;
	char *src;
	int type;
	int rotation;
	int indicator;
	int color_depth;
	int pid;
	char *effect_type;
	char *theme_type;
	guint timer;
};

struct rotation_s {
	sensor_t sensor;
	int handle;
	int angle;
	int auto_rotate;
	int charger_status;
	bool initialized;
	guint timer;
};

struct image_info_s {
	char *name;
	char *file;
	char *type;
	char *orientation;
	char *indicator_display;
	char *color_depth;
};

typedef struct splash_image_s *splash_image_h;
static struct wl_display *display;
static struct tizen_launch_effect *tz_launch_effect;
static int splash_screen_initialized;
static struct rotation_s rotation;
static GList *default_image_list;
static splash_image_h splash_image;
static splash_image_h cur_splash_image;
static uint32_t tz_launch_effect_id;

static int __init_splash_screen(void);
static int __init_rotation(void);

static splash_image_h __splash_screen_get_image(int pid)
{
	if (splash_image == NULL)
		return NULL;

	if (splash_image->pid == pid)
		return splash_image;

	return NULL;
}

static void __set_splash_image(splash_image_h si)
{
	splash_image = si;
}

static void __splash_screen_destroy_image(splash_image_h si)
{
	if (si == NULL)
		return;

	if (si->timer)
		g_source_remove(si->timer);
	if (si->theme_type)
		free(si->theme_type);
	if (si->effect_type)
		free(si->effect_type);
	if (si->appid)
		free(si->appid);
	if (si->src)
		free(si->src);
	if (si->image) {
		tizen_launch_splash_destroy(si->image);
		wl_display_flush(display);
	}
	free(si);
	__set_splash_image(NULL);
}

static gboolean __timeout_handler(gpointer data)
{
	splash_image_h si = (splash_image_h)data;
	amd_app_status_h app_status;

	if (si == NULL)
		return FALSE;

	app_status = amd_app_status_find_by_pid(si->pid);
	if (app_status) {
		if (amd_app_status_is_starting(app_status) == false) {
			LOGW("% is not starting", si->pid);
			return TRUE;
		}
	}

	si->timer = 0;
	__splash_screen_destroy_image(si);

	return FALSE;
}

static int __app_can_launch_splash_image(amd_appinfo_h ai, bundle *kb)
{
	const char *comp_type;
	const char *fake_effect;
	int display;

	comp_type = amd_appinfo_get_value(ai, AMD_AIT_COMPTYPE);
	if (comp_type == NULL || strcmp(comp_type, APP_TYPE_UI) != 0) {
		LOGD("component_type: %s", comp_type);
		return -1;
	}

	fake_effect = bundle_get_val(kb, K_FAKE_EFFECT);
	if (fake_effect && !strcmp(fake_effect, "OFF"))
		return -1;

	amd_appinfo_get_int_value(ai, AMD_AIT_SPLASH_SCREEN_DISPLAY, &display);
	if (!(display & APP_ENABLEMENT_MASK_ACTIVE))
		return -1;

	return 0;
}

static struct appinfo_splash_image *__get_splash_image_info(
		amd_appinfo_h ai, bundle *kb, int cmd)
{
	amd_appinfo_h caller_ai;
	amd_appinfo_splash_image_h image;
	const char *operation;
	const char *uid_str;
	const char *caller_appid;
	const char *comp_type;
	uid_t uid = 0;
	bool landscape;

	if ((rotation.angle == 90 || rotation.angle == 270)
				&& rotation.auto_rotate == true)
		landscape = true;
	else
		landscape = false;

	operation = bundle_get_val(kb, AUL_SVC_K_OPERATION);
	if (cmd == APP_OPEN || (operation &&
			(!strcmp(operation, APP_CONTROL_OPERATION_MAIN) ||
			 !strcmp(operation, AUL_SVC_OPERATION_DEFAULT)))) {
		return amd_appinfo_find_splash_image(ai, "launch-effect",
				landscape);
	}

	if (operation) {
		image = amd_appinfo_find_splash_image(ai, operation, landscape);
		if (image)
			return image;
	}

	caller_appid = bundle_get_val(kb, AUL_K_CALLER_APPID);
	if (caller_appid == NULL)
		return NULL;

	uid_str = bundle_get_val(kb, AUL_K_TARGET_UID);
	if (uid_str == NULL)
		return NULL;

	if (isdigit(*uid_str))
		uid = atol(uid_str);
	caller_ai = amd_appinfo_find(uid, caller_appid);
	if (caller_ai == NULL)
		return NULL;

	comp_type = amd_appinfo_get_value(caller_ai, AMD_AIT_COMPTYPE);
	if (comp_type == NULL)
		return NULL;

	if (!strcmp(comp_type, APP_TYPE_WATCH) ||
			!strcmp(comp_type, APP_TYPE_WIDGET)) {
		return amd_appinfo_find_splash_image(ai, "launch-effect",
				landscape);
	}

	return NULL;
}

static struct image_info_s *__get_default_image_info(bundle *kb)
{
	struct image_info_s *info = NULL;
	const char *orientation = "portrait";
	const char *str;
	GList *list;

	if (default_image_list == NULL)
		return NULL;

	if ((rotation.angle == 90 || rotation.angle == 270) &&
			rotation.auto_rotate == true)
		orientation = "landscape";

	str = bundle_get_val(kb, AUL_SVC_K_SPLASH_SCREEN);
	if (str == NULL)
		str = "default";

	list = default_image_list;
	while (list) {
		info = (struct image_info_s *)list->data;
		if (info && strcmp(str, info->name) == 0) {
			if (!strcasecmp(info->orientation, orientation))
				return info;
		}

		list = g_list_next(list);
	}

	return NULL;
}

static splash_image_h __splash_screen_create_image(amd_appinfo_h ai,
		bundle *kb, int cmd, bool is_subapp)
{
	amd_appinfo_splash_image_h image_info;
	struct splash_image_s *si;
	struct image_info_s *info;
	const char *appid;
	const char *src = NULL;
	const char *type;
	int file_type = 0;
	int indicator = 1;
	int color_depth = 24; /* default */

	if (!splash_screen_initialized) {
		if (__init_splash_screen() < 0)
			return NULL;
	}

	if (__app_can_launch_splash_image(ai, kb) < 0)
		return NULL;

	if (TIZEN_FEATURE_CHARGER_STATUS) {
		if (rotation.charger_status) {
			if (!rotation.initialized && __init_rotation() < 0)
				LOGW("Failed to initialize rotation");
		}
	} else {
		if (!rotation.initialized && __init_rotation() < 0)
			LOGW("Failed to initialize rotation");
	}
	LOGD("angle: %d", rotation.angle);

	image_info = __get_splash_image_info(ai, kb, cmd);
	if (image_info) {
		src = amd_appinfo_splash_image_get_source(image_info);
		if (access(src, F_OK) != 0)
			return NULL;
		type = amd_appinfo_splash_image_get_type(image_info);
		if (type && strcasecmp(type, "edj") == 0)
			file_type = 1;
		indicator = amd_appinfo_splash_image_get_indicator_display(
				image_info);;
		color_depth = amd_appinfo_splash_image_get_color_depth(
				image_info);
	} else {
		info = __get_default_image_info(kb);
		if (info == NULL)
			return NULL;
		src = info->file;
		if (access(src, F_OK) != 0)
			return NULL;
		if (strcasecmp(info->type, "edj") == 0)
			file_type = 1;
		if (strcmp(info->indicator_display, "false") == 0)
			indicator = 0;
		if (strcmp(info->color_depth, "32") == 0)
			color_depth = 32;
	}

	si = (struct splash_image_s *)calloc(1, sizeof(struct splash_image_s));
	if (si == NULL) {
		LOGE("out of memory");
		return NULL;
	}

	si->image = tizen_launch_effect_create_splash_img(
			tz_launch_effect);
	if (si->image == NULL) {
		LOGE("Failed to get launch image");
		free(si);
		return NULL;
	}
	wl_display_flush(display);

	si->src = strdup(src);
	if (si->src == NULL) {
		LOGE("out of memory");
		__splash_screen_destroy_image(si);
		return NULL;
	}

	if (is_subapp)
		si->effect_type = strdup("depth-in");
	else
		si->effect_type = strdup("launch");
	if (si->effect_type == NULL) {
		LOGE("Out of memory");
		__splash_screen_destroy_image(si);
		return NULL;
	}

	si->theme_type = strdup("default");
	if (si->theme_type == NULL) {
		LOGE("Out of memory");
		__splash_screen_destroy_image(si);
		return NULL;
	}

	appid = amd_appinfo_get_value(ai, AMD_AIT_NAME);
	si->appid = strdup(appid);
	if (si->appid == NULL) {
		LOGE("out of memory");
		__splash_screen_destroy_image(si);
		return NULL;
	}

	si->type = file_type;
	si->rotation = rotation.angle;
	si->indicator = indicator;
	si->color_depth = color_depth;

	si->timer = g_timeout_add(TIMEOUT_INTERVAL, __timeout_handler, si);
	__set_splash_image(si);

	return si;
}

static void __splash_screen_send_image(splash_image_h si)
{
	struct wl_array options;
	bundle *b;
	bundle_raw *raw_data = NULL;
	int len = 0;
	int ret;
	size_t size;
	void *data;

	if (si == NULL || si->image == NULL)
		return;

	wl_array_init(&options);

	b = bundle_create();
	if (b == NULL) {
		LOGE("out of memory");
		return;
	}

	bundle_add(b, AUL_K_APPID, si->appid);
	ret = bundle_encode(b, &raw_data, &len);
	if (ret != BUNDLE_ERROR_NONE) {
		LOGE("Failed to encode bundle");
		bundle_free(b);
		return;
	}
	bundle_free(b);

	size = strlen((const char *)raw_data);
	data = wl_array_add(&options, size + 1);
	memcpy(data, raw_data, size + 1);
	free(raw_data);

	LOGD("src(%s), type(%d), color-depth(%d), rotation(%d), " \
			"indicator(%d), effect_type(%s)",
			si->src, si->type, si->color_depth, si->rotation,
			si->indicator, si->effect_type);
	tizen_launch_splash_launch(si->image, si->src, si->type,
			si->color_depth, si->rotation, si->indicator,
			si->effect_type, si->theme_type, &options);
	wl_display_flush(display);

	wl_array_release(&options);
}

static void __splash_screen_send_pid(splash_image_h si, int pid)
{
	if (si == NULL)
		return;

	LOGD("pid(%d)", pid);
	si->pid = pid;
	tizen_launch_splash_owner(si->image, pid);
	wl_display_flush(display);
}

static void __splash_screen_set_effect_type(int pid, const char *appid, bool is_subapp)
{
	struct wl_array options;
	bundle *b;
	bundle_raw *raw_data = NULL;
	int len = 0;
	int ret;
	size_t size;
	void *data;
	const char *effect_type;

	if (!splash_screen_initialized)
		return;

	wl_array_init(&options);

	if (is_subapp)
		effect_type = "depth-in";
	else
		effect_type = "launch";

	b = bundle_create();
	if (b == NULL) {
		LOGE("out of memory");
		return;
	}

	bundle_add(b, AUL_K_APPID, appid);
	ret = bundle_encode(b, &raw_data, &len);
	if (ret != BUNDLE_ERROR_NONE) {
		LOGE("Failed to encode bundle");
		bundle_free(b);
		return;
	}
	bundle_free(b);

	size = strlen((const char *)raw_data);
	data = wl_array_add(&options, size + 1);
	memcpy(data, raw_data, size + 1);
	free(raw_data);

	LOGD("effect_type(%s), pid(%d)", effect_type, pid);
	tizen_launch_effect_type_set(tz_launch_effect, effect_type,
			pid, &options);
	wl_display_flush(display);

	wl_array_release(&options);
}

static int __init_splash_screen(void)
{
	if (!display) {
		display = amd_wayland_get_display();
		if (!display) {
			LOGE("Failed to get display");
			return -1;
		}
	}

	if (!tz_launch_effect) {
		LOGE("Failed to bind tizen launch screen");
		return -1;
	}

	splash_screen_initialized = 1;

	return 0;
}

static void __rotation_changed_cb(sensor_t sensor, unsigned int event_type,
		sensor_data_t *data, void *user_data)
{
	int event;

	if (event_type != AUTO_ROTATION_CHANGE_STATE_EVENT)
		return;

	event = (int)data->values[0];
	switch (event) {
	case AUTO_ROTATION_DEGREE_0:
		rotation.angle = 0;
		break;
	case AUTO_ROTATION_DEGREE_90:
		rotation.angle = 90;
		break;
	case AUTO_ROTATION_DEGREE_180:
		rotation.angle = 180;
		break;
	case AUTO_ROTATION_DEGREE_270:
		rotation.angle = 270;
		break;
	default:
		break;
	}

	LOGD("angle: %d", rotation.angle);
}

static void __auto_rotate_screen_cb(keynode_t *key, void *data)
{
	rotation.auto_rotate = vconf_keynode_get_bool(key);
	if (!rotation.auto_rotate) {
		LOGD("auto_rotate: %d, angle: %d",
				rotation.auto_rotate, rotation.angle);
	}
}

static void __fini_rotation(void)
{
	if (!rotation.initialized)
		return;

	if (!TIZEN_FEATURE_AUTO_ROTATION)
		return;

	vconf_ignore_key_changed(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL,
			__auto_rotate_screen_cb);
	sensord_unregister_event(rotation.handle,
			AUTO_ROTATION_CHANGE_STATE_EVENT);
	sensord_disconnect(rotation.handle);
	rotation.angle = 0;

	rotation.initialized = false;
}

static int __init_rotation(void)
{
	int ret;
	bool r;

	if (!TIZEN_FEATURE_AUTO_ROTATION) {
		rotation.initialized = true;
		return 0;
	}

	if (!rotation.sensor) {
		rotation.sensor = sensord_get_sensor(AUTO_ROTATION_SENSOR);
		if (!rotation.sensor) {
			LOGE("Failed to get sensor. errno(%d)", errno);
			return -1;
		}
	}

	rotation.angle = 0;
	rotation.handle = sensord_connect(rotation.sensor);
	if (rotation.handle < 0) {
		LOGW("Failed to connect sensord");
		return -1;
	}

	r = sensord_register_event(rotation.handle,
			AUTO_ROTATION_CHANGE_STATE_EVENT,
			SENSOR_INTERVAL_NORMAL,
			0,
			__rotation_changed_cb,
			NULL);
	if (!r) {
		LOGW("Failed to register event");
		sensord_disconnect(rotation.handle);
		return -1;
	}

	r = sensord_start(rotation.handle, 0);
	if (!r) {
		LOGW("Failed to start sensord");
		sensord_unregister_event(rotation.handle,
				AUTO_ROTATION_CHANGE_STATE_EVENT);
		sensord_disconnect(rotation.handle);
		return -1;
	}

	ret = vconf_get_bool(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL,
			&rotation.auto_rotate);
	if (ret != VCONF_OK)
		rotation.auto_rotate = false;

	ret = vconf_notify_key_changed(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL,
			__auto_rotate_screen_cb, NULL);
	if (ret != 0) {
		LOGW("Failed to register callback for %s",
				VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL);
	}
	rotation.initialized = true;

	return 0;
}

static void __destroy_image_info(struct image_info_s *info)
{
	if (info == NULL)
		return;

	if (info->color_depth)
		free(info->color_depth);
	if (info->indicator_display)
		free(info->indicator_display);
	if (info->type)
		free(info->type);
	if (info->orientation)
		free(info->orientation);
	if (info->file)
		free(info->file);
	if (info->name)
		free(info->name);
	free(info);
}

struct image_info_s *__create_image_info(void)
{
	struct image_info_s *info;

	info = (struct image_info_s *)calloc(1, sizeof(struct image_info_s));
	if (info == NULL) {
		LOGE("out of memory");
		return NULL;
	}

	return info;
}

static int __validate_image_info(struct image_info_s *info)
{
	if (!info || !info->name || !info->file || !info->orientation)
		return -1;

	if (!info->type) {
		if (strstr(info->file, "edj"))
			info->type = strdup("edj");
		else
			info->type = strdup("img");
		if (info->type == NULL) {
			LOGE("Out of memory");
			return -1;
		}
	}

	if (!info->indicator_display) {
		info->indicator_display = strdup("true");
		if (info->indicator_display == NULL) {
			LOGE("Out of memory");
			return -1;
		}
	}

	if (!info->color_depth) {
		info->color_depth = strdup("24");
		if (info->color_depth == NULL) {
			LOGE("Out of memory");
			return -1;
		}
	}

	return 0;
}

static void __parse_file(const char *file)
{
	FILE *fp;
	char buf[LINE_MAX];
	char *tok1 = NULL;
	char *tok2 = NULL;
	struct image_info_s *info = NULL;

	fp = fopen(file, "rt");
	if (fp == NULL)
		return;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		FREE_AND_NULL(tok1);
		FREE_AND_NULL(tok2);
		sscanf(buf, "%ms %ms", &tok1, &tok2);

		if (tok1 && strcasecmp(TAG_SPLASH_IMAGE, tok1) == 0) {
			if (info) {
				if (__validate_image_info(info) < 0) {
					__destroy_image_info(info);
				} else {
					default_image_list = g_list_append(
							default_image_list,
							info);
				}
			}
			info = __create_image_info();
			continue;
		}

		if (!tok1 || !tok2 || !info)
			continue;

		if (strcasecmp(TAG_NAME, tok1) == 0)
			info->name = strdup(tok2);
		else if (strcasecmp(TAG_FILE, tok1) == 0)
			info->file = strdup(tok2);
		else if (strcasecmp(TAG_TYPE, tok1) == 0)
			info->type = strdup(tok2);
		else if (strcasecmp(TAG_ORIENTATION, tok1) == 0)
			info->orientation = strdup(tok2);
		else if (strcasecmp(TAG_INDICATOR_DISPLAY, tok1) == 0)
			info->indicator_display = strdup(tok2);
		else if (strcasecmp(TAG_COLOR_DEPTH, tok1) == 0)
			info->color_depth = strdup(tok2);
	}

	if (info) {
		if (__validate_image_info(info) < 0) {
			__destroy_image_info(info);
		} else {
			default_image_list = g_list_append(default_image_list,
					info);
		}
	}

	if (tok1)
		free(tok1);
	if (tok2)
		free(tok2);

	fclose(fp);
}

static int __load_splash_screen_info(const char *path)
{
	DIR *dp;
	struct dirent *entry = NULL;
	char *ext;
	char buf[PATH_MAX];

	dp = opendir(path);
	if (dp == NULL)
		return -1;

	while ((entry = readdir(dp)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;

		ext = strrchr(entry->d_name, '.');
		if (ext && !strcmp(ext, ".conf")) {
			snprintf(buf, sizeof(buf), "%s/%s",
					path, entry->d_name);
			__parse_file(buf);
		}
	}

	closedir(dp);

	return 0;
}

static int __on_launch_start(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	int cmd = arg1;
	bundle *kb = data;
	amd_launch_context_h h = arg3;

	cur_splash_image = NULL;
	if (!amd_launch_context_get_instance_id(h) &&
			!amd_launch_context_is_bg_launch(h)) {
		cur_splash_image = __splash_screen_create_image(
				amd_launch_context_get_appinfo(h), kb, cmd,
				amd_launch_context_is_subapp(h));
		__splash_screen_send_image(cur_splash_image);
	}

	return 0;
}

static int __on_launch_end(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	amd_launch_context_h h = arg3;
	amd_appinfo_h ai = amd_launch_context_get_appinfo(h);
	const char *comp_type;

	comp_type = amd_appinfo_get_value(ai, AMD_AIT_COMPTYPE);
	if (cur_splash_image) {
		__splash_screen_send_pid(cur_splash_image,
				amd_launch_context_get_pid(h));
	} else if (comp_type && !strcmp(comp_type, APP_TYPE_UI)) {
		__splash_screen_set_effect_type(amd_launch_context_get_pid(h),
				amd_launch_context_get_appid(h),
				amd_launch_context_is_subapp(h));
	}

	return 0;
}

static int __on_launch_cancel(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	if (cur_splash_image) {
		__splash_screen_destroy_image(cur_splash_image);
		cur_splash_image = NULL;
	}

	return 0;
}

static int __on_cleanup(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	int pid = arg1;
	splash_image_h si;

	si = __splash_screen_get_image(pid);
	if (si)
		__splash_screen_destroy_image(si);

	return 0;
}

static int __on_wl_listener(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	uint32_t id = (uint32_t)arg1;
	struct wl_registry *registry = (struct wl_registry *)arg3;

	if (!tz_launch_effect) {
		tz_launch_effect_id = id;
		tz_launch_effect = wl_registry_bind(registry, id,
				&tizen_launch_effect_interface, 1);
		LOGD("tz_launch_effect(%p)", tz_launch_effect);
	}

	return 0;
}

static int __on_wl_listener_remove(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	uint32_t id = (uint32_t)arg1;

	if (id == tz_launch_effect_id && tz_launch_effect) {
		tizen_launch_effect_destroy(tz_launch_effect);
		tz_launch_effect = NULL;
		tz_launch_effect_id = 0;
		splash_screen_initialized = 0;
		LOGW("tizen launch effect is destroyed");
	}

	return 0;
}

static void __charger_status_changed_cb(keynode_t *keynode, void *user_data)
{
	if (TIZEN_FEATURE_CHARGER_STATUS) {
		rotation.charger_status = vconf_keynode_get_int(keynode);
		if (rotation.charger_status) {
			if (__init_rotation() < 0)
				LOGW("Failed to initialize rotation");
		} else {
			__fini_rotation();
		}
		LOGD("charger status(%d)", rotation.charger_status);
	}
}

static gboolean __rotation_init_handler(gpointer data)
{
	int r;

	if (TIZEN_FEATURE_CHARGER_STATUS) {
		r = vconf_get_int(VCONFKEY_SYSMAN_CHARGER_STATUS,
				&rotation.charger_status);
		if (r < 0) {
			LOGW("Failed to get charger status");
			return G_SOURCE_CONTINUE;
		}

		r = vconf_notify_key_changed(VCONFKEY_SYSMAN_CHARGER_STATUS,
				__charger_status_changed_cb, NULL);
		if (r < 0) {
			LOGW("Failed to register vconf cb");
			return G_SOURCE_CONTINUE;
		}

		if (rotation.charger_status) {
			if (__init_rotation() < 0)
				LOGW("Failed to initialize rotation");
		}
	} else {
		if (__init_rotation() < 0)
			LOGW("Failed to initialize rotation");
	}

	rotation.timer = 0;
	return G_SOURCE_REMOVE;
}

EXPORT int AMD_MOD_INIT(void)
{
	LOGD("splash screen init");

	__load_splash_screen_info(SPLASH_SCREEN_INFO_PATH);

	amd_noti_listen("wayland.listener.tizen_launch_effect",
			__on_wl_listener);
	amd_noti_listen("wayland.listener_remove", __on_wl_listener_remove);
	amd_noti_listen("launch.do_starting_app.start", __on_launch_start);
	amd_noti_listen("launch.do_starting_app.cancel",  __on_launch_cancel);
	amd_noti_listen("launch.do_starting_app.end", __on_launch_end);
	amd_noti_listen("main.app_dead", __on_cleanup);

	rotation.timer = g_timeout_add(500, __rotation_init_handler, NULL);

	return 0;
}

EXPORT void AMD_MOD_FINI(void)
{
	LOGD("splash screen finish");

	if (rotation.timer)
		g_source_remove(rotation.timer);

	vconf_ignore_key_changed(VCONFKEY_SYSMAN_CHARGER_STATUS,
			__charger_status_changed_cb);

	__fini_rotation();
}
