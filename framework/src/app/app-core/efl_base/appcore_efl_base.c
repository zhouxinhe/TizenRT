/*
 * Copyright (c) 2017 Samsung Electronics Co., Ltd. All rights reserved.
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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <glib.h>
#include <Elementary.h>
#include <vconf.h>

#include "appcore_efl_base_private.h"
#include "appcore_efl_base.h"

#define PATH_LIB_VC_ELM "/usr/lib/libvc-elm.so.0"

static bool __vc_elm_initialized;
static void *__vc_elm_handle;
static int (*__vc_elm_initialize)(void);
static int (*__vc_elm_deinitialize)(void);
static int (*__vc_elm_set_auto_register_mode)(int, int);
static GThread *__vc_elm_thread;

static void __unload_vc_elm(void)
{
	if (!__vc_elm_handle)
		return;

	__vc_elm_initialize = NULL;
	__vc_elm_deinitialize = NULL;
	__vc_elm_set_auto_register_mode = NULL;

	dlclose(__vc_elm_handle);
	__vc_elm_handle = NULL;
}

static int __load_vc_elm(void)
{
	_DBG("Load voice-control-elm");

	if (__vc_elm_handle) {
		_DBG("Already exists");
		return 0;
	}

	if (access(PATH_LIB_VC_ELM, F_OK) != 0) {
		_ERR("Failed to access %s", PATH_LIB_VC_ELM);
		return -1;
	}

	__vc_elm_handle = dlopen(PATH_LIB_VC_ELM, RTLD_LAZY | RTLD_LOCAL);
	if (!__vc_elm_handle) {
		_ERR("Failed to open %s", PATH_LIB_VC_ELM);
		return -1;
	}

	__vc_elm_initialize = dlsym(__vc_elm_handle, "vc_elm_initialize");
	if (!__vc_elm_initialize) {
		_ERR("Failed to load vc_elm_initialize");
		__unload_vc_elm();
		return -1;
	}

	__vc_elm_deinitialize = dlsym(__vc_elm_handle, "vc_elm_deinitialize");
	if (!__vc_elm_deinitialize) {
		_ERR("Failed to load vc_elm_deinitialize");
		__unload_vc_elm();
		return -1;
	}

	__vc_elm_set_auto_register_mode = dlsym(__vc_elm_handle,
			"vc_elm_set_auto_register_mode");
	if (!__vc_elm_set_auto_register_mode) {
		_ERR("Failed to load vc_elm_set_auto_register_mode");
		__unload_vc_elm();
		return -1;
	}

	return 0;
}

static void __vc_vtauto_changed_cb(keynode_t *key, void *data)
{
	const char *name;
	int vt_automode;

	name = vconf_keynode_get_name(key);
	if (!name || strcmp(name, VCONFKEY_VC_VOICE_TOUCH_AUTOMODE) != 0)
		return;

	vt_automode = vconf_keynode_get_bool(key);
	if (vt_automode) {
		if (!__vc_elm_initialized) {
			__vc_elm_initialize();
			__vc_elm_initialized = true;
		}
		__vc_elm_set_auto_register_mode(2, 0);
	} else {
		__vc_elm_deinitialize();
		__vc_elm_initialized = false;
	}
}

static void __vc_elm_init(void)
{
	int vt_automode = 0;

	vconf_notify_key_changed(VCONFKEY_VC_VOICE_TOUCH_AUTOMODE,
			__vc_vtauto_changed_cb, NULL);
	vconf_get_bool(VCONFKEY_VC_VOICE_TOUCH_AUTOMODE, &vt_automode);
	if (vt_automode) {
		if (!__vc_elm_initialized) {
			__vc_elm_initialize();
			__vc_elm_initialized = true;
		}
		__vc_elm_set_auto_register_mode(2, 0);
	}
}

static void __vc_elm_finish(void)
{
	vconf_ignore_key_changed(VCONFKEY_VC_VOICE_TOUCH_AUTOMODE,
			__vc_vtauto_changed_cb);
	if (__vc_elm_initialized) {
		__vc_elm_deinitialize();
		__vc_elm_initialized = false;
	}
}

static gboolean __init_vc_elm(gpointer data)
{
	_DBG("Initialize vc-elm");
	/* Postpone initialization to improve app launching performance */
	/* VC voice touch setting */
	__vc_elm_init();

	return G_SOURCE_REMOVE;
}

static gpointer __vc_elm_loader(gpointer data)
{
	int r = 0;
	int retry_count = 3;

	do {
		r = __load_vc_elm();
		if (r == 0) {
			g_idle_add(__init_vc_elm, NULL);
			break;
		}
	} while (retry_count--);
	LOGW("[vc-elm-loader] Result: %d", r);

	return GINT_TO_POINTER(r);
}

static void __efl_app_init(int argc, char **argv, void *data)
{
	int hint;
	const char *hwacc;

	elm_init(argc, argv);

	hint = appcore_efl_base_get_hint();
	if (hint & APPCORE_EFL_BASE_HINT_HW_ACC_CONTROL) {
		hwacc = getenv("HWACC");
		if (hwacc == NULL) {
			_DBG("elm_config_accel_preference_set is not called");
		} else if (strcmp(hwacc, "USE") == 0) {
			elm_config_accel_preference_set("hw");
			_DBG("elm_config_accel_preference_set : hw");
		} else if (strcmp(hwacc, "NOT_USE") == 0) {
			elm_config_accel_preference_set("none");
			_DBG("elm_config_accel_preference_set : none");
		} else {
			_DBG("elm_config_accel_preference_set is not called");
		}
	}

	__vc_elm_thread = g_thread_new("vc-elm-loader", __vc_elm_loader, NULL);
}

static void __efl_app_finish(void)
{
	gpointer r;

	__vc_elm_finish();
	if (__vc_elm_thread) {
		r = g_thread_join(__vc_elm_thread);
		__vc_elm_thread = NULL;
		_DBG("vc-elm-loader. result(%d)", GPOINTER_TO_INT(r));
	}

	elm_shutdown();

	/* Check loader case */
	if (getenv("AUL_LOADER_INIT")) {
		unsetenv("AUL_LOADER_INIT");
		elm_shutdown();
	}
}

static void __efl_app_run(void *data)
{
	elm_run();
}

static void __efl_app_exit(void *data)
{
	elm_exit();
}

static void __efl_app_trim_memory(void *data)
{
	_DBG("Trim memory");
	elm_cache_all_flush();
	appcore_base_on_trim_memory();
}

EXPORT_API int appcore_efl_base_init(appcore_efl_base_ops ops, int argc,
		char **argv, void *data, unsigned int hint)
{
	return appcore_ui_base_init(ops.ui_base, argc, argv, data, hint);
}

EXPORT_API void appcore_efl_base_fini(void)
{
	appcore_ui_base_fini();
}

EXPORT_API appcore_efl_base_ops appcore_efl_base_get_default_ops(void)
{
	appcore_efl_base_ops ops;

	ops.ui_base = appcore_ui_base_get_default_ops();

	/* override methods */
	ops.ui_base.base.init = __efl_app_init;
	ops.ui_base.base.finish = __efl_app_finish;
	ops.ui_base.base.run = __efl_app_run;
	ops.ui_base.base.exit = __efl_app_exit;
	ops.ui_base.base.trim_memory = __efl_app_trim_memory;

	return ops;
}

EXPORT_API int appcore_efl_base_on_receive(aul_type type, bundle *b)
{
	return appcore_ui_base_on_receive(type, b);
}

EXPORT_API int appcore_efl_base_on_create(void)
{
	return appcore_ui_base_on_create();
}

EXPORT_API int appcore_efl_base_on_terminate(void)
{
	return appcore_ui_base_on_terminate();
}

EXPORT_API int appcore_efl_base_on_pause(void)
{
	return appcore_ui_base_on_pause();
}

EXPORT_API int appcore_efl_base_on_resume(void)
{
	return appcore_ui_base_on_resume();
}

EXPORT_API int appcore_efl_base_on_control(bundle *b)
{
	return appcore_ui_base_on_control(b);
}

EXPORT_API int appcore_efl_base_on_trim_memory(void)
{
	return appcore_ui_base_on_trim_memory();
}

EXPORT_API void appcore_efl_base_window_on_show(int type, void *event)
{
	appcore_ui_base_window_on_show(type, event);
}

EXPORT_API void appcore_efl_base_window_on_hide(int type, void *event)
{
	appcore_ui_base_window_on_hide(type, event);
}

EXPORT_API void appcore_efl_base_window_on_lower(int type, void *event)
{
	appcore_ui_base_window_on_lower(type, event);
}

EXPORT_API void appcore_efl_base_window_on_visibility(int type, void *event)
{
	appcore_ui_base_window_on_visibility(type, event);
}

EXPORT_API void appcore_efl_base_pause(void)
{
	appcore_ui_base_pause();
}

EXPORT_API void appcore_efl_base_resume(void)
{
	appcore_ui_base_resume();
}

EXPORT_API bool appcore_efl_base_is_resumed(void)
{
	return appcore_ui_base_is_resumed();
}

EXPORT_API void appcore_efl_base_exit(void)
{
	appcore_ui_base_exit();
}

EXPORT_API void appcore_efl_base_group_add(void)
{
	appcore_ui_base_group_add();
}

EXPORT_API void appcore_efl_base_group_remove(void)
{
	appcore_ui_base_group_remove();
}

EXPORT_API unsigned int appcore_efl_base_get_main_window(void)
{
	return appcore_ui_base_get_main_window();
}

EXPORT_API unsigned int appcore_efl_base_get_main_surface(void)
{
	return appcore_ui_base_get_main_surface();
}

EXPORT_API int appcore_efl_base_get_hint(void)
{
	return appcore_ui_base_get_hint();
}

EXPORT_API bool appcore_efl_base_get_bg_state(void)
{
	return appcore_ui_base_get_bg_state();
}

EXPORT_API void appcore_efl_base_set_bg_state(bool bg_state)
{
	appcore_ui_base_set_bg_state(bg_state);
}

EXPORT_API void appcore_efl_base_set_system_resource_reclaiming(bool enable)
{
	appcore_ui_base_set_system_resource_reclaiming(enable);
}
