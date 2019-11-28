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
#include <gio/gio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <bundle_internal.h>
#include <aul.h>
#include <aul_sock.h>
#include <vconf.h>

#include "amd_config.h"
#include "amd_signal.h"
#include "amd_util.h"
#include "amd_suspend.h"
#include "amd_app_status.h"

typedef struct proc_info {
	pid_t pid;
	guint timer_id;
} proc_info_t;

typedef struct network_info {
	bool vconf_initialized;
	bool disconnected;
	guint timer_id;
} network_info_t;

static GHashTable *proc_info_tbl;
static network_info_t __net_info;
static guint __init_timer;

static void __destroy_proc_info_value(gpointer data)
{
	proc_info_t *proc = (proc_info_t *)data;

	if (proc)
		free(proc);
}

static bool __network_is_disconnected(int status)
{
	switch (status) {
	case VCONFKEY_NETWORK_CELLULAR:
		_D("Cellular type");
		return false;
	case VCONFKEY_NETWORK_WIFI:
		_D("Wi-Fi type");
		return false;
	case VCONFKEY_NETWORK_ETHERNET:
		_D("Ethernet type");
		return false;
	case VCONFKEY_NETWORK_BLUETOOTH:
		_D("Bluetooth type");
		return false;
	case VCONFKEY_NETWORK_DEFAULT_PROXY:
		_D("Proxy type for internet connection");
		return false;
	default:
		_D("Disconnected");
		return true;
	}
}

static void __prepare_to_suspend(int pid, uid_t uid)
{
	int ret;
	int dummy = 0;

	_D("[__SUSPEND__] pid: %d, uid: %d", pid, uid);
	ret = aul_sock_send_raw(pid, uid, APP_SUSPEND, (unsigned char *)&dummy,
			sizeof(int), AUL_SOCK_NOREPLY);
	if (ret < 0)
		_E("Failed to send APP_SUSPEND %d", pid);
}

static void __prepare_to_wake(int pid, uid_t uid)
{
	int ret;
	bundle *kb;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return;
	}

	bundle_add(kb, AUL_K_ALLOWED_BG, "ALLOWED_BG");

	_D("[__SUSPEND__] pid: %d, uid: %d", pid, uid);
	ret = aul_sock_send_bundle(pid, uid, APP_WAKE, kb, AUL_SOCK_NOREPLY);
	if (ret != AUL_R_OK)
		_E("Failed to send APP_WAKE %d", pid);

	bundle_free(kb);
}

static void __wake_bg_apps(app_status_h app_status, void *data)
{
	const char *appid;
	int status;
	uid_t uid;
	const struct appinfo *ai;
	int target_category;
	int bg_category;
	bool bg_allowed;
	int pid;

	if (app_status == NULL)
		return;

	status = _app_status_get_status(app_status);
	if (status != STATUS_BG && status != STATUS_SERVICE)
		return;

	appid = _app_status_get_appid(app_status);
	uid = _app_status_get_uid(app_status);
	pid = _app_status_get_pid(app_status);

	ai = _appinfo_find(uid, appid);
	if (ai == NULL)
		return;

	if (data) {
		target_category = GPOINTER_TO_INT(data);
		bg_category = (intptr_t)_appinfo_get_value(ai, AIT_BG_CATEGORY);
		if (bg_category != target_category)
			return;
	} else {
		bg_allowed = _suspend_is_allowed_background(ai);
		if (bg_allowed == true)
			return;
	}

	_D("[__SUSPEND__] Wake %s %d", appid, pid);
	_suspend_remove_timer(pid);
	__prepare_to_wake(pid, uid);
	_app_status_find_service_apps(app_status, status,
			__prepare_to_wake, false);
	aul_update_freezer_status(pid, "exclude");
}

static void __suspend_bg_apps(app_status_h app_status, void *data)
{
	const char *appid;
	int status;
	uid_t uid;
	const struct appinfo *ai;
	int target_category;
	int bg_category;
	bool bg_allowed;
	int pid;

	if (app_status == NULL)
		return;

	status = _app_status_get_status(app_status);
	if (status != STATUS_BG && status != STATUS_SERVICE)
		return;

	appid = _app_status_get_appid(app_status);
	uid = _app_status_get_uid(app_status);
	pid = _app_status_get_pid(app_status);

	ai = _appinfo_find(uid, appid);
	if (ai == NULL)
		return;

	if (data) {
		target_category = GPOINTER_TO_INT(data);
		bg_category = (intptr_t)_appinfo_get_value(ai, AIT_BG_CATEGORY);
		if (bg_category != target_category)
			return;
	} else {
		bg_allowed = _suspend_is_allowed_background(ai);
		if (bg_allowed == true)
			return;
	}

	_D("[__SUSPEND__] Suspend %s %d", appid, pid);
	_app_status_find_service_apps(app_status, status,
			__prepare_to_suspend, true);
	__prepare_to_suspend(pid, uid);
	_suspend_add_timer(pid);
	aul_update_freezer_status(pid, "include");
}

static gboolean __handle_bg_network_apps(gpointer data)
{
	int bg_category = BACKGROUND_CATEGORY_BACKGROUND_NETWORK;

	if (__net_info.disconnected) {
		_D("[__SUSPEND__] Network is disconnected");
		_app_status_foreach_running_appinfo(__suspend_bg_apps,
				GINT_TO_POINTER(bg_category));
	} else {
		_D("[__SUSPEND__] Network is connected");
		_app_status_foreach_running_appinfo(__wake_bg_apps,
				GINT_TO_POINTER(bg_category));
	}

	__net_info.timer_id = 0;
	return G_SOURCE_REMOVE;
}

static void __network_info_add_timer(void)
{
	if (__net_info.timer_id)
		g_source_remove(__net_info.timer_id);

	__net_info.timer_id = g_timeout_add(500, __handle_bg_network_apps, NULL);
}

static void __network_info_remove_timer(void)
{
	if (__net_info.timer_id) {
		g_source_remove(__net_info.timer_id);
		__net_info.timer_id = 0;
	}
}

static void __network_status_changed_cb(keynode_t *key, void *data)
{
	int status;
	bool disconnected;

	status = vconf_keynode_get_int(key);
	disconnected = __network_is_disconnected(status);
	if (__net_info.disconnected != disconnected) {
		_W("[__SUSPEND__] Network status(%d -> %d) is changed",
				__net_info.disconnected, disconnected);
		__net_info.disconnected = disconnected;
		__network_info_add_timer();
	}
}

static gboolean __init_network_info(gpointer data)
{
	int r;
	int status = 0;

	r = vconf_get_int(VCONFKEY_NETWORK_STATUS, &status);
	if (r != VCONF_OK)
		_E("Failed to get network status");
	else
		__net_info.disconnected = __network_is_disconnected(status);

	r = vconf_notify_key_changed(VCONFKEY_NETWORK_STATUS,
			__network_status_changed_cb, NULL);
	if (r != VCONF_OK) {
		_E("Failed to add vconf notify cb");
		return G_SOURCE_CONTINUE;
	}

	__network_info_add_timer();
	__net_info.vconf_initialized = true;

	_D("[__SUSPEND__] Network info is initialized");

	__init_timer = 0;
	return G_SOURCE_REMOVE;
}

static void __fini_network_info()
{
	__network_info_remove_timer();

	if (__net_info.vconf_initialized) {
		vconf_ignore_key_changed(VCONFKEY_NETWORK_STATUS,
				__network_status_changed_cb);
		__net_info.vconf_initialized = false;
	}
	_D("[__SUSPEND__] Network info is finished");
}

void _suspend_init(void)
{
	if (!proc_info_tbl) {
		proc_info_tbl = g_hash_table_new_full(g_direct_hash,
				g_direct_equal, NULL,
				__destroy_proc_info_value);
	}

	__init_timer = g_timeout_add(500, __init_network_info, NULL);

	_D("_amd_proc_init done");
}

void _suspend_fini(void)
{
	if (__init_timer)
		g_source_remove(__init_timer);

	__fini_network_info();

	g_hash_table_destroy(proc_info_tbl);
	_D("_amd_proc_fini done");
}

proc_info_t *__create_proc_info(int pid)
{
	proc_info_t *proc;

	if (pid < 1) {
		_E("invalid pid");
		return NULL;
	}

	proc = (proc_info_t *)malloc(sizeof(proc_info_t));
	if (proc == NULL) {
		_E("insufficient memory");
		return NULL;
	}

	proc->pid = pid;
	proc->timer_id = 0;

	return proc;
}

proc_info_t *__find_proc_info(int pid)
{
	proc_info_t *proc;

	if (pid < 1) {
		_E("invalid pid");
		return NULL;
	}

	proc = (proc_info_t *)g_hash_table_lookup(proc_info_tbl,
			GINT_TO_POINTER(pid));
	if (proc == NULL) {
		_E("proc info not found");
		return NULL;
	}

	return proc;
}

int __add_proc_info(proc_info_t *proc)
{
	if (proc == NULL) {
		_E("invalid proc info");
		return -1;
	}

	if (proc->pid < 1) {
		_E("invalid pid");
		return -1;
	}

	g_hash_table_insert(proc_info_tbl, GINT_TO_POINTER(proc->pid), proc);

	return 0;
}

int _suspend_add_proc(int pid)
{
	proc_info_t *proc;

	proc = __create_proc_info(pid);
	if (proc)
		return __add_proc_info(proc);

	return -1;
}

int _suspend_remove_proc(int pid)
{
	proc_info_t *proc;

	if (pid < 1) {
		_E("invalid pid");
		return -1;
	}

	proc = (proc_info_t *)g_hash_table_lookup(proc_info_tbl,
			GINT_TO_POINTER(pid));
	if (proc == NULL) {
		_E("proc info not found");
		return -1;
	}

	g_hash_table_remove(proc_info_tbl, GINT_TO_POINTER(pid));

	return 0;
}

static gboolean __send_suspend_hint(gpointer data)
{
	proc_info_t *proc;
	int pid = GPOINTER_TO_INT(data);

	proc = __find_proc_info(pid);
	if (proc && proc->timer_id > 0) {
		_signal_send_proc_suspend(pid);
		proc->timer_id = 0;
	}

	return FALSE;
}

bool _suspend_is_allowed_background(const struct appinfo *ai)
{
	int bg_category;
	const char *comp_type;

	comp_type = _appinfo_get_value(ai, AIT_COMPTYPE);
	if (comp_type == NULL)
		return false;

	if (strcmp(comp_type, APP_TYPE_UI) &&
			strcmp(comp_type, APP_TYPE_SERVICE))
		return true;

	/*
	 * 2.4 bg-categorized (uiapp || svcapp) || watch || widget -> bg allowed
	 * 2.3 uiapp -> not allowed, 2.3 svcapp -> bg allowed
	 */
	bg_category = (intptr_t)_appinfo_get_value(ai, AIT_BG_CATEGORY);
	if (bg_category) {
		if (__net_info.disconnected) {
			if (bg_category &
				(~(int)BACKGROUND_CATEGORY_BACKGROUND_NETWORK))
				return true;
		} else {
			return true;
		}
	}

	return false;
}

void _suspend_add_timer(int pid)
{
	proc_info_t *proc;

	proc = __find_proc_info(pid);
	if (proc == NULL) {
		proc = __create_proc_info(pid);
		if (proc)
			__add_proc_info(proc);
	}

	if (proc) {
		proc->timer_id = g_timeout_add_seconds(10, __send_suspend_hint,
				GINT_TO_POINTER(pid));
	}
}

void _suspend_remove_timer(int pid)
{
	proc_info_t *proc;

	proc = __find_proc_info(pid);
	if (proc && proc->timer_id > 0) {
		g_source_remove(proc->timer_id);
		proc->timer_id = 0;
	}
}

int _suspend_update_status(int pid, int status)
{
	app_status_h app_status;

	if (pid < 0)
		return -1;

	app_status = _app_status_find(pid);
	if (app_status == NULL)
		return -1;

	if (status == SUSPEND_STATUS_EXCLUDE) {
		__wake_bg_apps(app_status, NULL);
	} else if (status == SUSPEND_STATUS_INCLUDE) {
		__suspend_bg_apps(app_status, NULL);
	} else {
		_E("Unknown status(%d)", status);
		return -1;
	}
	_D("[__SUSPEND__] pid(%d), status(%d)", pid, status);

	return 0;
}
