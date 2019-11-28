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
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <uuid/uuid.h>
#include <glib.h>
#include <aul.h>
#include <string.h>
#include <linux/limits.h>
#include <vconf.h>
#include <time.h>
#include <aul_sock.h>
#include <aul_proc.h>
#include <ctype.h>
#include <gio/gio.h>
#include <bundle_internal.h>

#include "amd_app_status.h"
#include "amd_appinfo.h"
#include "amd_request.h"
#include "amd_launch.h"
#include "amd_util.h"
#include "amd_suspend.h"
#include "amd_socket.h"
#include "amd_app_com.h"
#include "amd_signal.h"
#include "amd_noti.h"
#include "amd_inotify.h"
#include "amd_proc.h"

#define PATH_AUL_APPS "/run/aul/apps"

struct pkg_status_s {
	char *pkgid;
	int status;
	GSList *ui_list;
	GSList *svc_list;
};

struct app_status_s {
	char *appid;
	char *app_path;
	char *pkgid;
	char *instance_id;
	int app_type;
	int pid;
	uid_t uid;
	int status;
	bool is_subapp;
	int leader_pid;
	int timestamp;
	int fg_count;
	bool managed;
	int org_caller_pid;
	int last_caller_pid;
	struct pkg_status_s *pkg_status;
	bool bg_launch;
	bool socket_exists;
	bool starting;
	GHashTable *extras;
	bool exiting;
	bool debug_mode;
	guint timer;
};

struct fault_app_s {
	int pid;
	int uid;
	char *appid;
	char *pkgid;
	int type;
};

struct vconf_context_s {
	bool initialized;
	guint timer;
};

static GSList *app_status_list;
static GHashTable *pkg_status_table;
static int limit_bg_uiapps;
static char *home_appid;
static GHashTable *__wd_table;
static inotify_watch_info_h __wh;
static struct vconf_context_s __vconf;

static int __get_managed_uiapp_cnt(void)
{
	GSList *iter;
	struct app_status_s *app_status;
	int cnt = 0;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->managed &&
				app_status->app_type == AT_UI_APP)
			cnt++;
	}

	return cnt;
}

static void __cleanup_bg_uiapps(int n)
{
	GSList *iter;
	GSList *iter_next;
	struct app_status_s *app_status;
	int i = 0;
	int ret;

	GSLIST_FOREACH_SAFE(app_status_list, iter, iter_next) {
		if (i == n)
			break;

		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->status != STATUS_VISIBLE) {
			ret = _terminate_app_local(app_status->uid,
					app_status->pid);
			if (ret < 0) {
				_E("Failed to terminate app(%d)",
						app_status->pid);
				continue;
			}
			i++;
		}
	}
}

static void __check_running_uiapp_list(void)
{
	_noti_send("app_status.term_bg_apps", 0, 0, NULL, NULL);
}

int _app_status_term_bg_apps(GCompareFunc func)
{
	int len;
	int n;

	len = __get_managed_uiapp_cnt();
	if (len <= 0)
		return -1;

	n = len - limit_bg_uiapps;
	if (n <= 0)
		return -1;

	app_status_list = g_slist_sort(app_status_list, func);
	__cleanup_bg_uiapps(n);

	return 0;
}

static void __vconf_cb(keynode_t *key, void *data)
{
	const char *name;

	name = vconf_keynode_get_name(key);
	if (name && strcmp(name, VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS) == 0) {
		limit_bg_uiapps = vconf_keynode_get_int(key);
		if (limit_bg_uiapps > 0)
			__check_running_uiapp_list();
	}
}

static void __update_leader_app_status(int leader_pid)
{
	GSList *iter;
	struct app_status_s *app_status;

	if (leader_pid <= 0)
		return;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->pid == leader_pid) {
			app_status->timestamp = time(NULL) / 10;
			app_status->fg_count++;
			break;
		}
	}
}

static void __add_pkg_status(struct app_status_s *app_status)
{
	struct pkg_status_s *pkg_status;

	if (app_status == NULL) {
		_E("Invalid parameter");
		return;
	}

	if (app_status->app_type != AT_SERVICE_APP &&
			app_status->app_type != AT_UI_APP)
		return;

	if (pkg_status_table == NULL) {
		pkg_status_table = g_hash_table_new(g_str_hash, g_str_equal);
		if (pkg_status_table == NULL) {
			_E("out of memory");
			return;
		}
	}

	pkg_status = g_hash_table_lookup(pkg_status_table, app_status->pkgid);
	if (pkg_status == NULL) {
		pkg_status = (struct pkg_status_s *)calloc(1,
				sizeof(struct pkg_status_s));
		if (pkg_status == NULL) {
			_E("out of memory");
			return;
		}

		pkg_status->pkgid = strdup(app_status->pkgid);
		if (pkg_status->pkgid == NULL) {
			_E("out of memory");
			free(pkg_status);
			return;
		}

		g_hash_table_insert(pkg_status_table, pkg_status->pkgid,
				pkg_status);
	}

	pkg_status->status = app_status->status;
	app_status->pkg_status = pkg_status;

	if (app_status->app_type == AT_SERVICE_APP) {
		pkg_status->svc_list = g_slist_append(pkg_status->svc_list,
				app_status);
	} else {
		pkg_status->ui_list = g_slist_append(pkg_status->ui_list,
				app_status);
	}
}

static int __get_ui_app_status_pkg_status(struct pkg_status_s *pkg_status)
{
	struct app_status_s *app_status;
	GSList *iter;

	for (iter = pkg_status->ui_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status->status != STATUS_BG)
			return app_status->status;
	}

	return STATUS_BG;
}

static int __update_pkg_status(struct app_status_s *app_status)
{
	struct pkg_status_s *pkg_status;
	int ret;

	if (app_status == NULL)
		return -1;

	if (pkg_status_table == NULL)
		return -1;

	pkg_status = (struct pkg_status_s *)g_hash_table_lookup(
			pkg_status_table, app_status->pkgid);
	if (pkg_status == NULL) {
		_E("pkgid(%s) is not on list", app_status->pkgid);
		return -1;
	}

	if (pkg_status->ui_list) {
		ret = __get_ui_app_status_pkg_status(pkg_status);
		if (ret > -1)
			pkg_status->status = ret;
	} else {
		pkg_status->status = STATUS_SERVICE;
	}

	return 0;
}

static void __remove_pkg_status(struct app_status_s *app_status)
{
	struct pkg_status_s *pkg_status;

	if (app_status == NULL) {
		_E("Invalid parameter");
		return;
	}

	pkg_status = g_hash_table_lookup(pkg_status_table, app_status->pkgid);
	if (pkg_status == NULL)
		return;

	if (app_status->app_type == AT_SERVICE_APP) {
		pkg_status->svc_list = g_slist_remove(pkg_status->svc_list,
				app_status);
		_D("STATUS_SERVICE: appid(%s)", app_status->appid);
	} else {
		pkg_status->ui_list = g_slist_remove(pkg_status->ui_list,
				app_status);
		_D("~STATUS_SERVICE: appid(%s)", app_status->appid);
	}

	if (!pkg_status->svc_list && !pkg_status->ui_list) {
		g_hash_table_remove(pkg_status_table, pkg_status->pkgid);
		if (pkg_status->pkgid)
			free(pkg_status->pkgid);
		free(pkg_status);
	}
}

static void __destroy_app_status(struct app_status_s *app_status)
{
	if (app_status == NULL)
		return;

	_noti_send("app_status.destroy", 0, 0, app_status, NULL);

	if (app_status->instance_id)
		free(app_status->instance_id);
	if (app_status->pkgid)
		free(app_status->pkgid);
	if (app_status->app_path)
		free(app_status->app_path);
	if (app_status->appid)
		free(app_status->appid);
	if (app_status->extras)
		g_hash_table_destroy(app_status->extras);
	if (app_status->timer)
		g_source_remove(app_status->timer);

	free(app_status);
}

static int __get_app_type(const char *comp_type)
{
	if (comp_type == NULL)
		return -1;

	if (strcmp(comp_type, APP_TYPE_SERVICE) == 0)
		return AT_SERVICE_APP;
	else if (strcmp(comp_type, APP_TYPE_UI) == 0)
		return AT_UI_APP;
	else if (strcmp(comp_type, APP_TYPE_WIDGET) == 0)
		return AT_WIDGET_APP;
	else if (strcmp(comp_type, APP_TYPE_WATCH) == 0)
		return AT_WATCH_APP;

	return -1;
}

static int __app_status_set_app_info(struct app_status_s *app_status,
		const struct appinfo *ai, int pid,
		bool is_subapp, uid_t uid, int caller_pid,
		bool bg_launch, const char *instance_id,
		bool debug_mode)
{
	const char *appid;
	const char *app_path;
	const char *pkgid;
	const char *comp_type;
	const char *taskmanage;
	char buf[MAX_PACKAGE_STR_SIZE];
	char uuid[37];
	uuid_t u;

	appid = _appinfo_get_value(ai, AIT_NAME);
	if (appid == NULL)
		return -1;

	app_status->appid = strdup(appid);
	if (app_status->appid == NULL) {
		_E("out of memory");
		return -1;
	}

	app_path = _appinfo_get_value(ai, AIT_EXEC);
	if (app_path == NULL)
		return -1;

	app_status->app_path = strdup(app_path);
	if (app_status->app_path == NULL) {
		_E("out of memory");
		return -1;
	}

	pkgid = _appinfo_get_value(ai, AIT_PKGID);
	if (pkgid == NULL)
		return -1;

	app_status->pkgid = strdup(pkgid);
	if (app_status->pkgid == NULL) {
		_E("out of memory");
		return -1;
	}

	comp_type = _appinfo_get_value(ai, AIT_COMPTYPE);
	if (comp_type == NULL)
		return -1;

	app_status->app_type = __get_app_type(comp_type);
	if (app_status->app_type == -1) {
		_E("Unknown component type: %s", comp_type);
		return -1;
	}

	if (app_status->app_type == AT_SERVICE_APP)
		app_status->status = STATUS_SERVICE;
	else
		app_status->status = STATUS_LAUNCHING;

	if (instance_id) {
		app_status->instance_id = strdup(instance_id);
		if (app_status->instance_id == NULL) {
			_E("out of memory");
			return -1;
		}
	} else {
		uuid_generate(u);
		uuid_unparse(u, uuid);

		snprintf(buf, sizeof(buf), "%s:%s", uuid, appid);
		app_status->instance_id = strdup(buf);
		if (app_status->instance_id == NULL) {
			_E("out of memory");
			return -1;
		}
	}

	app_status->pid = pid;
	app_status->uid = uid;
	app_status->is_subapp = is_subapp;
	app_status->timestamp = time(NULL) / 10;
	app_status->org_caller_pid = caller_pid;
	app_status->last_caller_pid = caller_pid;

	taskmanage = _appinfo_get_value(ai, AIT_TASKMANAGE);
	if (taskmanage && strcmp(taskmanage, "true") == 0 &&
			app_status->leader_pid > 0 &&
			app_status->is_subapp == false)
		app_status->managed = true;

	app_status->bg_launch = bg_launch;
	app_status->socket_exists = false;
	app_status->starting = false;
	app_status->extras = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
	app_status->debug_mode = debug_mode;
	app_status->exiting = false;

	return 0;
}

int _app_status_set_extra(app_status_h app_status, const char *key, void *data)
{
	char *name;

	if (!app_status || !app_status->extras)
		return -1;

	name = strdup(key);
	if (!name)
		return -1;

	_app_status_remove_extra(app_status, key);
	if (g_hash_table_insert(app_status->extras, name, data) == TRUE)
		return 0;

	return -1;
}

int _app_status_remove_extra(app_status_h app_status, const char *key)
{
	if (!app_status || !app_status->extras)
		return -1;

	if (g_hash_table_remove(app_status->extras, key) == TRUE)
		return 0;

	return -1;
}

void *_app_status_get_extra(app_status_h app_status, const char *key)
{
	if (!app_status || !app_status->extras)
		return NULL;

	return g_hash_table_lookup(app_status->extras, key);
}

int _app_status_add_app_info(const struct appinfo *ai, int pid,
		bool is_subapp, uid_t uid, int caller_pid,
		bool bg_launch, const char *instance_id,
		bool debug_mode)
{
	GSList *iter;
	GSList *iter_next;
	struct app_status_s *app_status;
	int r;

	if (ai == NULL)
		return -1;

	GSLIST_FOREACH_SAFE(app_status_list, iter, iter_next) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->pid == pid) {
			if (app_status->uid == uid)
				return 0;

			app_status_list = g_slist_remove(app_status_list,
					app_status);
			__remove_pkg_status(app_status);
			__destroy_app_status(app_status);
			break;
		}
	}

	app_status = (struct app_status_s *)calloc(1,
			sizeof(struct app_status_s));
	if (app_status == NULL) {
		_E("out of memory");
		return -1;
	}

	r = __app_status_set_app_info(app_status, ai, pid, is_subapp, uid,
			caller_pid, bg_launch, instance_id, debug_mode);
	if (r < 0) {
		__destroy_app_status(app_status);
		return -1;
	}

	_noti_send("app_status.add", 0, 0, app_status, NULL);
	app_status_list = g_slist_append(app_status_list, app_status);
	__add_pkg_status(app_status);

	return 0;
}

int _app_status_remove_all_app_info_with_uid(uid_t uid)
{
	GSList *iter;
	GSList *iter_next;
	struct app_status_s *app_status;

	GSLIST_FOREACH_SAFE(app_status_list, iter, iter_next) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->uid == uid) {
			app_status_list = g_slist_remove(app_status_list,
					app_status);
			__destroy_app_status(app_status);
		}
	}

	return 0;
}

int _app_status_remove(app_status_h app_status)
{
	if (app_status == NULL)
		return -1;

	app_status_list = g_slist_remove(app_status_list, app_status);
	__remove_pkg_status(app_status);
	__destroy_app_status(app_status);

	return 0;
}

static gboolean __terminate_timer_cb(gpointer data)
{
	int pid = GPOINTER_TO_INT(data);
	app_status_h app_status;
	int r;

	app_status = _app_status_find(pid);
	if (app_status == NULL)
		return G_SOURCE_REMOVE;

	_E("pid(%d)", pid);
	r = kill(pid, SIGKILL);
	if (r < 0)
		_W("Failed to send SIGKILL, pid(%d), errno(%d)", pid, errno);
	app_status->timer = 0;

	return G_SOURCE_REMOVE;
}

int _app_status_update_status(app_status_h app_status, int status, bool force,
		bool update_group_info)
{
	if (app_status == NULL || status < 0)
		return -1;

	_D("pid: %d, status: %d", app_status->pid, status);
	_noti_send("app_status.update_status.start", status, 0,
			app_status, NULL);
	if (app_status->status == STATUS_DYING) {
		_E("%s is STATUS_DYING", app_status->appid);
		return -1;
	}

	app_status->status = status;
	if (app_status->status == STATUS_VISIBLE) {
		app_status->timestamp = time(NULL) / 10;
		app_status->fg_count++;
		if (!app_status->managed)
			__update_leader_app_status(app_status->leader_pid);
		if (app_status->fg_count == 1 && limit_bg_uiapps > 0)
			__check_running_uiapp_list();
	} else if (app_status->status == STATUS_DYING) {
		_suspend_remove_timer(app_status->pid);
		if (!app_status->debug_mode) {
			app_status->timer = g_timeout_add_seconds(5,
					__terminate_timer_cb,
					GINT_TO_POINTER(app_status->pid));
		}
		aul_send_app_terminate_request_signal(app_status->pid,
				NULL, NULL, NULL);
	}

	__update_pkg_status(app_status);
	_W("pid: %d, appid: %s, pkgid: %s, status: %s(%d)",
			app_status->pid, app_status->appid, app_status->pkgid,
			aul_app_status_convert_to_string(app_status->status),
			app_status->status);
	_noti_send("app_status.update_status.end", force, update_group_info,
			app_status, NULL);

	return 0;
}

int _app_status_update_last_caller_pid(app_status_h app_status, int caller_pid)
{
	if (app_status == NULL)
		return -1;

	app_status->last_caller_pid = caller_pid;

	return 0;
}

int _app_status_update_bg_launch(app_status_h app_status, bool bg_launch)
{
	if (app_status == NULL)
		return -1;

	if (!app_status->bg_launch)
		return 0;

	app_status->bg_launch = bg_launch;

	return 0;
}

int _app_status_get_process_cnt(const char *appid)
{
	GSList *iter;
	struct app_status_s *app_status;
	int cnt = 0;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->appid &&
				strcmp(app_status->appid, appid) == 0)
			cnt++;
	}

	return cnt;
}

bool _app_status_is_home_app(app_status_h app_status)
{
	const char *appid = _app_status_get_appid(app_status);

	if (!appid)
		return false;
	if (!home_appid)
		return false;

	if (strcmp(home_appid, appid) == 0)
		return true;

	return false;
}

int _app_status_get_pid(app_status_h app_status)
{
	if (app_status == NULL)
		return -1;

	return app_status->pid;
}

int _app_status_get_org_caller_pid(app_status_h app_status)
{
	if (app_status == NULL)
		return -1;

	return app_status->org_caller_pid;
}

int _app_status_get_last_caller_pid(app_status_h app_status)
{
	if (app_status == NULL)
		return -1;

	return app_status->last_caller_pid;
}

int _app_status_is_running(app_status_h app_status)
{
	if (app_status == NULL ||
		(app_status->app_type == AT_UI_APP && app_status->is_subapp) ||
		app_status->status == STATUS_DYING)
		return -1;

	return app_status->pid;
}

int _app_status_get_status(app_status_h app_status)
{
	if (app_status == NULL)
		return -1;

	return app_status->status;
}

uid_t _app_status_get_uid(app_status_h app_status)
{
	if (app_status == NULL)
		return (uid_t)-1;

	return app_status->uid;
}

const char *_app_status_get_appid(app_status_h app_status)
{
	if (app_status == NULL)
		return NULL;

	return app_status->appid;
}

const char *_app_status_get_pkgid(app_status_h app_status)
{
	if (app_status == NULL)
		return NULL;

	return app_status->pkgid;
}

bool _app_status_get_bg_launch(app_status_h app_status)
{
	if (app_status == NULL)
		return false;

	return app_status->bg_launch;
}

const char *_app_status_get_instance_id(app_status_h app_status)
{
	if (app_status == NULL)
		return NULL;

	return app_status->instance_id;
}

int _app_status_get_app_type(app_status_h app_status)
{
	if (app_status == NULL)
		return -1;

	return app_status->app_type;
}

bool _app_status_socket_exists(app_status_h app_status)
{
	if (app_status == NULL)
		return false;

	return app_status->socket_exists;
}

bool _app_status_is_starting(app_status_h app_status)
{
	if (app_status == NULL)
		return false;

	return app_status->starting;
}

int _app_status_update_is_starting(app_status_h app_status, bool is_starting)
{
	if (app_status == NULL)
		return -1;

	app_status->starting = is_starting;

	return 0;
}

bool _app_status_is_exiting(app_status_h app_status)
{
	if (app_status == NULL)
		return false;

	return app_status->exiting;
}

int _app_status_update_is_exiting(app_status_h app_status, bool is_exiting)
{
	if (app_status == NULL)
		return -1;

	app_status->exiting = is_exiting;

	return 0;
}

const char *_app_status_get_app_path(app_status_h app_status)
{
	if (app_status == NULL)
		return NULL;

	return app_status->app_path;
}

app_status_h _app_status_find(int pid)
{
	GSList *iter;
	struct app_status_s *app_status;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->pid == pid)
			return app_status;
	}

	return NULL;
}

static int __read_ppid_from_proc(const char *path, int *ppid)
{
	FILE *fp;
	int ret;
	int result = -1;
	char *buf = NULL;
	int val;

	if (path == NULL)
		return -1;

	fp = fopen(path, "r");
	if (fp == NULL)
		return -1;

	ret = fscanf(fp, "%ms %d\n", &buf, &val);
	while (ret != EOF) {
		if (ret == 2) {
			if (buf && strcmp(buf, "PPid:") == 0) {
				*ppid = val;
				result = 0;
				_D("ppid : %d", *ppid);
				break;
			}
		}

		free(buf);
		buf = NULL;
		ret = fscanf(fp, "%ms %d\n", &buf, &val);
	}

	fclose(fp);
	free(buf);

	return result;
}

int __proc_get_ppid_by_pid(int pid)
{
	char path[PATH_MAX] = { 0, };
	int ret = 0;
	int ppid;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	ret = __read_ppid_from_proc(path, &ppid);
	if (ret < 0)
		return -1;

	return ppid;
}

app_status_h _app_status_find_v2(int pid)
{
	int ppid;
	int pgid;
	struct app_status_s *app_status;

	app_status = _app_status_find(pid);
	if (app_status == NULL) {
		pgid = getpgid(pid);
		if (pgid > 0)
			app_status = _app_status_find(pgid);
	}

	if (app_status == NULL) {
		ppid = __proc_get_ppid_by_pid(pid);
		app_status = _app_status_find(ppid);
	}

	return app_status;
}

app_status_h _app_status_find_by_appid(const char *appid, uid_t uid)
{
	GSList *iter;
	struct app_status_s *app_status;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->appid &&
				strcmp(app_status->appid, appid) == 0 &&
				app_status->uid == uid &&
				(app_status->is_subapp == false ||
				 app_status->app_type == AT_WATCH_APP ||
				 app_status->app_type == AT_WIDGET_APP))
			return app_status;
	}

	return NULL;
}

app_status_h _app_status_find_by_appid_v2(const char *appid, uid_t uid)
{
	GSList *iter;
	struct app_status_s *app_status;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->appid &&
				strcmp(app_status->appid, appid) == 0 &&
				app_status->uid == uid)
			return app_status;
	}

	return NULL;
}

app_status_h _app_status_find_with_org_caller(const char *appid, uid_t uid,
		int caller_pid)
{
	GSList *iter;
	struct app_status_s *app_status;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->appid &&
				strcmp(app_status->appid, appid) == 0 &&
				app_status->uid == uid &&
				app_status->org_caller_pid == caller_pid)
			return app_status;
	}

	return NULL;
}

app_status_h _app_status_find_by_instance_id(const char *appid,
		const char *instance_id, uid_t uid)
{
	GSList *iter;
	struct app_status_s *app_status;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->instance_id &&
				app_status->uid == uid &&
				!strcmp(app_status->instance_id, instance_id) &&
				!strcmp(app_status->appid, appid))
			return app_status;
	}

	return NULL;
}

void _app_status_find_service_apps(app_status_h app_status, int status,
		void (*send_event_to_svc_core)(int, uid_t), bool suspend)
{
	GSList *iter;
	GSList *svc_list = NULL;
	const struct appinfo *ai;
	struct app_status_s *svc_status;
	bool bg_allowed;
	uid_t uid;

	if (app_status == NULL) {
		_E("Invalid parameter");
		return;
	}

	uid = _app_status_get_uid(app_status);
	if (app_status->pkg_status && app_status->pkg_status->status == status)
		svc_list = app_status->pkg_status->svc_list;

	for (iter = svc_list; iter; iter = g_slist_next(iter)) {
		svc_status = (struct app_status_s *)iter->data;
		if (svc_status && svc_status->uid == uid) {
			ai = _appinfo_find(uid, svc_status->appid);
			bg_allowed = _suspend_is_allowed_background(ai);
			if (!bg_allowed) {
				send_event_to_svc_core(svc_status->pid, uid);
				if (svc_status->status != STATUS_DYING &&
						suspend)
					_suspend_add_timer(svc_status->pid);
				else
					_suspend_remove_timer(svc_status->pid);
			}
		}
	}
}

void _app_status_check_service_only(app_status_h app_status,
		void (*send_event_to_svc_core)(int, uid_t))
{
	GSList *iter;
	GSList *ui_list = NULL;
	struct app_status_s *ui_status;
	int ui_cnt = 0;
	bool bg_allowed;
	const char *appid;
	const struct appinfo *ai;
	uid_t uid;
	int status;

	if (app_status == NULL) {
		_E("Invalid parameter");
		return;
	}

	uid = _app_status_get_uid(app_status);
	if (app_status->pkg_status && app_status->pkg_status->ui_list)
		ui_list = app_status->pkg_status->ui_list;

	for (iter = ui_list; iter; iter = g_slist_next(iter)) {
		ui_status = (struct app_status_s *)iter->data;
		if (_app_status_get_status(ui_status) != STATUS_DYING)
			ui_cnt++;
	}

	if (ui_cnt == 0) {
		appid = _app_status_get_appid(app_status);
		status = _app_status_get_status(app_status);
		ai = _appinfo_find(uid, appid);
		bg_allowed = _suspend_is_allowed_background(ai);
		if (!bg_allowed && status != STATUS_DYING) {
			send_event_to_svc_core(app_status->pid, uid);
			_suspend_add_timer(app_status->pid);
		}
	}
}

static bundle *__create_appinfo_bundle(app_status_h app_status)
{
	bundle *b;
	char tmp_str[MAX_PID_STR_BUFSZ];

	b = bundle_create();
	if (b == NULL)
		return NULL;

	snprintf(tmp_str, sizeof(tmp_str), "%d", app_status->pid);
	bundle_add(b, AUL_K_PID, tmp_str);
	bundle_add(b, AUL_K_APPID, app_status->appid);
	bundle_add(b, AUL_K_EXEC, app_status->app_path);
	bundle_add(b, AUL_K_PKGID, app_status->pkgid);
	snprintf(tmp_str, sizeof(tmp_str), "%d", app_status->status);
	bundle_add(b, AUL_K_STATUS, tmp_str);
	snprintf(tmp_str, sizeof(tmp_str), "%d", app_status->is_subapp);
	bundle_add(b, AUL_K_IS_SUBAPP, tmp_str);
	if (app_status->instance_id)
		bundle_add(b, AUL_K_INSTANCE_ID, app_status->instance_id);

	return b;
}

static int __send_running_appinfo(app_status_h app_status, int fd)
{
	int ret;
	bundle *b;
	bundle_raw *raw = NULL;
	int len = 0;

	b = __create_appinfo_bundle(app_status);
	if (b == NULL) {
		_E("out of memory");
		aul_sock_send_raw_with_fd(fd, APP_GET_INFO_ERROR,
				NULL, 0, AUL_SOCK_NOREPLY);
		return -1;
	}

	ret = bundle_encode(b, &raw, &len);
	bundle_free(b);
	if (ret != BUNDLE_ERROR_NONE) {
		_E("Failed to encode bundle");
		aul_sock_send_raw_with_fd(fd, APP_GET_INFO_ERROR, NULL,
				0, AUL_SOCK_NOREPLY);
		return -1;
	}

	ret = aul_sock_send_raw_with_fd(fd, APP_GET_INFO_OK,
			(unsigned char *)raw, len,
			AUL_SOCK_ASYNC | AUL_SOCK_BUNDLE);
	if (ret < 0) {
		_E("Failed to send raw data: %s", raw);
		free(raw);
		return ret;
	}
	free(raw);

	return 0;
}

int _app_status_send_running_appinfo(int fd, int cmd, uid_t uid)
{
	GSList *list = NULL;
	GSList *iter;
	struct app_status_s *app_status;
	int ret;
	int count;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status->uid != uid ||
				app_status->status == STATUS_DYING)
			continue;
		if (cmd != APP_ALL_RUNNING_INFO &&
				cmd != APP_RUNNING_INSTANCE_INFO &&
				(app_status->app_type == AT_UI_APP &&
				 app_status->is_subapp))
			continue;
		if (cmd == APP_RUNNING_INSTANCE_INFO &&
				app_status->instance_id == NULL)
			continue;

		list = g_slist_append(list, app_status);
	}

	count = g_slist_length(list);
	if (count == 0) {
		_E("Applications are not running");
		_send_result_to_client(fd, -1);
		return -1;
	}
	_send_result_to_client_v2(fd, count);

	for (iter = list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status == NULL)
			continue;

		ret = __send_running_appinfo(app_status, fd);
		if (ret < 0) {
			g_slist_free(list);
			return -1;
		}
	}
	close(fd);
	g_slist_free(list);

	return 0;
}

int _app_status_foreach_running_appinfo(void (*callback)(app_status_h, void *),
		void *data)
{
	GSList *iter;
	struct app_status_s *app_status;

	if (callback == NULL)
		return -1;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status->status == STATUS_DYING ||
				app_status->is_subapp)
			continue;
		callback(app_status, data);
	}

	return 0;
}

int _app_status_terminate_apps(const char *appid, uid_t uid)
{
	GSList *iter;
	struct app_status_s *app_status;
	int ret;

	if (appid == NULL)
		return -1;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status->uid == uid &&
				strcmp(app_status->appid, appid) == 0 &&
				app_status->status != STATUS_DYING) {
			ret = _terminate_app_local(app_status->uid,
					app_status->pid);
			if (ret < 0) {
				_E("Failed to terminate app(%d)",
						app_status->pid);
			}
		}
	}

	return 0;
}

int _app_status_terminate_apps_by_pkgid(const char *pkgid, uid_t uid)
{
	GSList *iter;
	struct app_status_s *app_status;
	int ret;

	if (pkgid == NULL)
		return -1;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status->uid == uid &&
				strcmp(app_status->pkgid, pkgid) == 0 &&
				app_status->status != STATUS_DYING) {
			ret = _terminate_app_local(app_status->uid,
					app_status->pid);
			if (ret < 0) {
				_E("Failed to terminate app(%d)",
						app_status->pid);
			}
		}
	}

	return 0;
}

int _app_status_get_appid_bypid(int fd, int pid)
{
	int cmd = APP_GET_INFO_ERROR;
	int len = 0;
	int pgid;
	int ppid;
	int ret;
	char appid[MAX_PACKAGE_STR_SIZE] = {0,};
	app_status_h app_status;

	app_status = _app_status_find(pid);
	if (app_status == NULL) {
		pgid = getpgid(pid);
		if (pgid > 0) {
			app_status = _app_status_find(pgid);
			if (app_status == NULL) {
				ppid = __proc_get_ppid_by_pid(pid);
				app_status = _app_status_find(ppid);
			}
		}
	}

	if (app_status) {
		snprintf(appid, sizeof(appid), "%s",
				_app_status_get_appid(app_status));
		SECURE_LOGD("appid for %d is %s", pid, appid);
		len = strlen(appid);
		cmd = APP_GET_INFO_OK;
	}

	ret = aul_sock_send_raw_with_fd(fd, cmd, (unsigned char *)appid,
			len, AUL_SOCK_NOREPLY);

	return ret;
}

int _app_status_get_pkgid_bypid(int fd, int pid)
{
	int cmd = APP_GET_INFO_ERROR;
	int len = 0;
	int pgid;
	int ppid;
	int ret;
	char pkgid[MAX_PACKAGE_STR_SIZE] = {0,};
	app_status_h app_status;

	app_status = _app_status_find(pid);
	if (app_status == NULL) {
		pgid = getpgid(pid);
		if (pgid > 0) {
			app_status = _app_status_find(pgid);
			if (app_status == NULL) {
				ppid = __proc_get_ppid_by_pid(pid);
				app_status = _app_status_find(ppid);
			}
		}
	}

	if (app_status) {
		snprintf(pkgid, sizeof(pkgid), "%s",
				_app_status_get_pkgid(app_status));
		SECURE_LOGD("pkgid for %d is %s", pid, pkgid);
		len = strlen(pkgid);
		cmd = APP_GET_INFO_OK;
	}

	ret = aul_sock_send_raw_with_fd(fd, cmd, (unsigned char *)pkgid,
			len, AUL_SOCK_NOREPLY);

	return ret;
}

int _app_status_get_instance_id_bypid(int fd, int pid)
{
	int cmd = APP_GET_INFO_ERROR;
	int len = 0;
	int ret;
	const char *instance_id;
	char buf[MAX_PACKAGE_STR_SIZE] = {0,};
	app_status_h app_status;

	app_status = _app_status_find(pid);
	if (app_status == NULL) {
		app_status = _app_status_find(getpgid(pid));
		if (app_status == NULL) {
			app_status = _app_status_find(
					__proc_get_ppid_by_pid(pid));
		}
	}

	instance_id = _app_status_get_instance_id(app_status);
	if (instance_id) {
		snprintf(buf, sizeof(buf), "%s", instance_id);
		SECURE_LOGD("pid(%d), instance-id(%s)", pid, instance_id);
		len = strlen(buf);
		cmd = APP_GET_INFO_OK;
	}

	ret = aul_sock_send_raw_with_fd(fd, cmd, (unsigned char *)buf, len,
			AUL_SOCK_NOREPLY);

	return ret;
}

int _app_status_set_leader_pid(app_status_h app_status, int pid)
{
	if (app_status == NULL)
		return -1;


	app_status->leader_pid = pid;

	return 0;
}

int _app_status_get_leader_pid(app_status_h app_status)
{
	if (app_status == NULL)
		return -1;


	return app_status->leader_pid;
}

int _app_status_get_fg_cnt(app_status_h app_status)
{
	if (app_status == NULL)
		return -1;


	return app_status->fg_count;
}

int _app_status_get_timestamp(app_status_h app_status)
{
	if (app_status == NULL)
		return -1;


	return app_status->timestamp;
}

static void __home_appid_vconf_cb(keynode_t *key, void *data)
{
	char *tmpstr;

	tmpstr = vconf_keynode_get_str(key);
	if (tmpstr == NULL)
		return;

	if (home_appid)
		free(home_appid);
	home_appid = strdup(tmpstr);
}

int _app_status_publish_status(int pid, int context_status)
{
	bundle *b;
	char endpoint_system[MAX_LOCAL_BUFSZ];
	char endpoint_user[MAX_LOCAL_BUFSZ];
	bool endpoint_system_exists;
	bool endpoint_user_exists;
	char buf[MAX_PID_STR_BUFSZ];
	app_status_h app_status;
	const char *appid;
	uid_t uid;

	app_status = _app_status_find(pid);
	if (app_status == NULL)
		return -1;

	appid = _app_status_get_appid(app_status);
	uid = _app_status_get_uid(app_status);
	snprintf(endpoint_user, sizeof(endpoint_user),
			"app_status_event:%s:%d", appid, uid);
	snprintf(endpoint_system, sizeof(endpoint_system),
			"app_status_event:%s", appid);
	endpoint_system_exists = _app_com_endpoint_exists(endpoint_system);
	endpoint_user_exists = _app_com_endpoint_exists(endpoint_user);
	if (!endpoint_system_exists && !endpoint_user_exists)
		return -1;

	b = __create_appinfo_bundle(app_status);
	if (b == NULL) {
		_E("Out of memory");
		return -1;
	}

	snprintf(buf, sizeof(buf), "%d", context_status);
	bundle_add(b, "__CONTEXT_STATUS__", buf);
	if (endpoint_system_exists)
		_app_com_send(endpoint_system, pid, b, uid);
	if (endpoint_user_exists)
		_app_com_send(endpoint_user, pid, b, uid);
	bundle_free(b);

	return 0;
}

static void __terminate_widget_apps_by_org_caller(int caller_pid, uid_t uid)
{
	GSList *iter;
	struct app_status_s *app_status;
	int ret;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if ((app_status->app_type == AT_WIDGET_APP ||
				app_status->app_type == AT_WATCH_APP) &&
				app_status->uid == uid &&
				app_status->org_caller_pid == caller_pid &&
				app_status->status != STATUS_DYING) {
			ret = _terminate_app_local(app_status->uid,
					app_status->pid);
			if (ret < 0) {
				_E("Failed to terminate app(%d)",
						app_status->pid);
			}
		}
	}
}

void _app_status_cleanup(app_status_h app_status)
{
	int pid;
	const char *instance_id;
	uid_t uid;

	if (app_status == NULL)
		return;

	pid = _app_status_get_pid(app_status);
	uid = _app_status_get_uid(app_status);
	_D("pid: %d, uid: %d", pid, uid);

	_noti_send("app_status.cleanup", pid, uid, app_status, NULL);

	instance_id = _app_status_get_instance_id(app_status);
	if (instance_id == NULL)
		instance_id = _app_status_get_appid(app_status);

	__terminate_widget_apps_by_org_caller(pid, uid);
	_app_com_client_remove(pid);
	_suspend_remove_proc(pid);
	_app_status_remove(app_status);
	aul_send_app_terminated_signal(pid);
}

static bool __socket_monitor_cb(const char *event_name, void *data)
{
	int pid = -1;

	if (event_name == NULL)
		return true;

	if (isdigit(*event_name))
		pid = atoi(event_name);

	if (pid > 1)
		_I("Socket(%d) is created.", pid);

	return true;
}

static bool __dir_monitor_cb(const char *event_name, void *data)
{
	uid_t uid;
	inotify_watch_info_h handle;
	char path[PATH_MAX];

	if (event_name == NULL)
		return true;

	uid = strtol(event_name, NULL, 10);
	handle = g_hash_table_lookup(__wd_table, GUINT_TO_POINTER(uid));
	if (!handle) {
		snprintf(path, sizeof(path), "%s/%u", PATH_AUL_APPS, uid);
		handle = _inotify_add_watch(path, IN_CREATE,
				__socket_monitor_cb, NULL);
		if (handle == NULL) {
			_E("Failed to add a watch - uid(%d)", uid);
			return true;;
		}

		g_hash_table_insert(__wd_table, GUINT_TO_POINTER(uid), handle);
	}

	return true;
}

int _app_status_usr_init(uid_t uid)
{
	inotify_watch_info_h handle;
	char buf[PATH_MAX];

	handle = g_hash_table_lookup(__wd_table, GUINT_TO_POINTER(uid));
	if (handle) {
		_D("Already exists. uid(%u)", uid);
		return 0;
	}

	snprintf(buf, sizeof(buf), "/run/aul/apps/%d", uid);
	if (access(buf, F_OK) == 0) {
		handle = _inotify_add_watch(buf, IN_CREATE, __socket_monitor_cb,
				NULL);
		if (handle == NULL) {
			_E("Failed to add a watch - uid(%d)", uid);
			return -1;
		}

		g_hash_table_insert(__wd_table, GUINT_TO_POINTER(uid), handle);
	}

	return 0;
}

void _app_status_usr_fini(uid_t uid)
{
	GSList *iter;
	GSList *iter_next;
	app_status_h app_status;

	if (g_hash_table_contains(__wd_table, GUINT_TO_POINTER(uid)))
		g_hash_table_remove(__wd_table, GUINT_TO_POINTER(uid));
	else
		_D("Watch fd doesn't exist - uid(%d)", uid);

	GSLIST_FOREACH_SAFE(app_status_list, iter, iter_next) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->uid == uid)
			_app_status_cleanup(app_status);
	}
}

static void __remove_inotify_watch(gpointer data)
{
	inotify_watch_info_h handle = data;

	if (handle == NULL)
		return;

	_inotify_rm_watch(handle);
}

static int __dispatch_app_running_info(request_h req)
{
	int ret;

	ret = _app_status_send_running_appinfo(_request_remove_fd(req),
			_request_get_cmd(req), _request_get_target_uid(req));
	return ret;
}

static int __dispatch_app_all_running_info(request_h req)
{
	int ret;

	ret = _app_status_send_running_appinfo(_request_remove_fd(req),
			_request_get_cmd(req), _request_get_target_uid(req));
	return ret;
}

static int __dispatch_app_is_running(request_h req)
{
	const char *appid;
	int ret;
	app_status_h app_status;
	bundle *b = _request_get_bundle(req);

	if (b == NULL) {
		_E("Failed to get bundle");
		_request_send_result(req, -1);
		return -1;
	}

	appid = bundle_get_val(b, AUL_K_APPID);
	if (appid == NULL) {
		_E("Failed to get appid");
		_request_send_result(req, -1);
		return -1;
	}

	app_status = _app_status_find_by_appid(appid,
			_request_get_target_uid(req));
	ret = _app_status_is_running(app_status);
	SECURE_LOGD("APP_IS_RUNNING : %s : %d", appid, ret);
	_request_send_result(req, ret);

	return 0;
}

static int __dispatch_app_get_pid(request_h req)
{
	const char *appid;
	int ret;
	app_status_h app_status;
	bundle *b;

	b = _request_get_bundle(req);
	if (b == NULL) {
		_E("Failed to get bundle");
		_request_send_result(req, -1);
		return -1;
	}

	appid = bundle_get_val(b, AUL_K_APPID);
	if (appid == NULL) {
		_E("Failed to get appid");
		_request_send_result(req, -1);
		return -1;
	}

	app_status = _app_status_find_by_appid(appid,
			_request_get_target_uid(req));
	ret = _app_status_get_pid(app_status);
	SECURE_LOGD("APP_GET_PID : %s : %d", appid, ret);
	_request_send_result(req, ret);

	return 0;
}

static int __dispatch_app_get_appid_by_pid(request_h req)
{
	int pid;
	int ret;
	const char *pid_str;
	bundle *b = _request_get_bundle(req);

	if (b == NULL) {
		_E("Failed to get bundle");
		aul_sock_send_raw_with_fd(_request_remove_fd(req),
				APP_GET_INFO_ERROR, NULL, 0, AUL_SOCK_NOREPLY);
		return -1;
	}

	pid_str = bundle_get_val(b, AUL_K_PID);
	if (pid_str == NULL || !isdigit(pid_str[0])) {
		_E("Failed to get pid");
		aul_sock_send_raw_with_fd(_request_remove_fd(req),
				APP_GET_INFO_ERROR, NULL, 0, AUL_SOCK_NOREPLY);
		return -1;
	}

	pid = atoi(pid_str);
	ret = _app_status_get_appid_bypid(_request_remove_fd(req), pid);
	_D("app_status_get_appid_bypid : %d : %d", pid, ret);

	return 0;
}

static int __dispatch_app_get_pkgid_by_pid(request_h req)
{
	int pid;
	int ret;
	const char *pid_str;
	bundle *b = _request_get_bundle(req);

	if (b == NULL) {
		_E("Failed to get bundle");
		aul_sock_send_raw_with_fd(_request_remove_fd(req),
				APP_GET_INFO_ERROR, NULL, 0, AUL_SOCK_NOREPLY);
		return -1;
	}

	pid_str = bundle_get_val(b, AUL_K_PID);
	if (pid_str == NULL || !isdigit(pid_str[0])) {
		_E("Failed to get pid");
		aul_sock_send_raw_with_fd(_request_remove_fd(req),
				APP_GET_INFO_ERROR, NULL, 0, AUL_SOCK_NOREPLY);
		return -1;
	}

	pid = atoi(pid_str);
	ret = _app_status_get_pkgid_bypid(_request_remove_fd(req), pid);
	_D("APP_GET_PKGID_BYPID : %d : %d", pid, ret);

	return 0;
}

static int __dispatch_app_status_update(request_h req)
{
	int *status;
	const char *appid;
	struct appinfo *ai;
	app_status_h app_status;

	app_status = _app_status_find(_request_get_pid(req));
	if (app_status == NULL)
		return -1;

	status = (int *)_request_get_raw(req);
	switch (*status) {
	case STATUS_NORESTART:
		appid = _app_status_get_appid(app_status);
		ai = _appinfo_find(_request_get_target_uid(req), appid);
		_appinfo_set_value((struct appinfo *)ai, AIT_STATUS,
				"norestart");
		break;
	case STATUS_VISIBLE:
	case STATUS_BG:
		break;
	default:
		_app_status_update_status(app_status, *status, false, true);
		break;
	}

	return 0;
}

static int __dispatch_app_get_status(request_h req)
{
	int pid;
	int status;
	app_status_h app_status;
	const char *pid_str;
	bundle *b;

	b = _request_get_bundle(req);
	if (b == NULL) {
		_E("Failed to get bundle");
		_request_send_result(req, -1);
		return -1;
	}

	pid_str = bundle_get_val(b, AUL_K_PID);
	if (pid_str == NULL || !isdigit(pid_str[0])) {
		_E("Falied to get pid");
		_request_send_result(req, -1);
		return -1;
	}

	pid = atoi(pid_str);
	app_status = _app_status_find(pid);
	status = _app_status_get_status(app_status);
	_request_send_result(req, status);

	return 0;
}

static int __dispatch_app_get_status_by_appid(request_h req)
{
	int status;
	int pid;
	uid_t uid;
	const char *appid;
	bundle *kb;
	app_status_h app_status;

	kb = _request_get_bundle(req);
	if (kb == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	uid = _request_get_target_uid(req);
	appid = bundle_get_val(kb, AUL_K_APPID);
	if (appid == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	app_status = _app_status_find_by_appid(appid, uid);
	pid = _app_status_is_running(app_status);
	status = _app_status_get_status(app_status);
	if (status == STATUS_VISIBLE) {
		if (_launch_get_focused_pid() == pid)
			status = STATUS_FOCUS;
	}

	_request_send_result(req, status);
	_D("appid: %s, pid: %d, status: %d", appid, pid, status);

	return 0;
}

static int __dispatch_app_get_last_caller_pid(request_h req)
{
	int pid;
	int ret;
	app_status_h app_status;
	const char *pid_str;
	bundle *b = _request_get_bundle(req);

	if (b == NULL) {
		_E("Failed to get bundle");
		_request_send_result(req, -1);
		return -1;
	}

	pid_str = bundle_get_val(b, AUL_K_PID);
	if (pid_str == NULL || !isdigit(pid_str[0])) {
		_E("Failed to get pid");
		_request_send_result(req, -1);
		return -1;
	}

	pid = atoi(pid_str);
	app_status = _app_status_find(pid);
	if (app_status == NULL) {
		_E("Failed to get app status info(%d)", pid);
		_request_send_result(req, -1);
		return -1;
	}

	ret = _app_status_get_last_caller_pid(app_status);
	_D("app_get_last_caller_pid: %d : %d", pid, ret);
	_request_send_result(req, ret);

	return 0;
}

static int __verify_app_process(pid_t pid, const char *pkgid)
{
	char attr[PATH_MAX] = { 0, };
	char buf[PATH_MAX];
	int r;

	r = _proc_get_attr(pid, attr, sizeof(attr));
	if (r < 0)
		return -1;

	snprintf(buf, sizeof(buf), "User::Pkg::%s", pkgid);
	if (!strcmp(buf, attr))
		return 0;

	SECURE_LOGD("attr:%s, package:%s", attr, pkgid);
	return -1;
}

int _app_status_register_pid(int pid, const char *appid, uid_t uid)
{
	struct appinfo *ai;
	const char *component_type;
	const char *pkgid;
	int ret;
	app_status_h app_status;
	int status = -1;
	int focused = -1;

	ai = _appinfo_find(uid, appid);
	if (!ai)
		return -1;

	pkgid = _appinfo_get_value(ai, AIT_PKGID);
	if (__verify_app_process(pid, pkgid) < 0)
		return -1;

	app_status = _app_status_find_by_appid(appid, uid);
	ret = _app_status_is_running(app_status);
	if (ret > 0) {
		_W("status info is already exist: %s", appid);
		if (ret == pid)
			return 0;
		_W("Running process: %d, request process:%d", ret, pid);
		return -1;
	}
	_D("appid: %s, pid: %d", appid, pid);

	component_type = _appinfo_get_value(ai, AIT_COMPTYPE);
	_noti_send("app_status.app_register_pid", pid, 0, ai, NULL);
	_app_status_add_app_info(ai, pid, false, uid, getpid(),
			false, NULL, false);
	if (component_type && strcmp(component_type, APP_TYPE_SERVICE) != 0) {
		ret = _signal_get_proc_status(pid, &status, &focused);
		if (ret < 0)
			return 0;

		if (focused == 1)
			_launch_set_focused_pid(pid);

		if (status == PROC_STATUS_FG)
			status = STATUS_VISIBLE;
		else if (status == PROC_STATUS_BG)
			status = STATUS_BG;
		else
			return -1;

		app_status = _app_status_find(pid);
		if (app_status == NULL)
			return -1;

		_app_status_update_status(app_status, status, false, true);
	}

	return 0;
}

static int __dispatch_app_register_pid(request_h req)
{
	uid_t target_uid = _request_get_target_uid(req);
	const char *appid;
	const char *pid_str;
	bundle *kb;
	int pid;

	kb = _request_get_bundle(req);
	if (kb == NULL)
		return -1;

	appid = bundle_get_val(kb, AUL_K_APPID);
	if (appid == NULL)
		return -1;

	pid_str = bundle_get_val(kb, AUL_K_PID);
	if (pid_str == NULL)
		return -1;

	pid = atoi(pid_str);
	if (pid <= 1)
		return -1;

	return _app_status_register_pid(pid, appid, target_uid);
}

static int __dispatch_app_running_instance_info(request_h req)
{
	int fd = _request_remove_fd(req);
	int cmd = _request_get_cmd(req);
	uid_t target_uid = _request_get_target_uid(req);

	return _app_status_send_running_appinfo(fd, cmd, target_uid);
}

static int __dispatch_app_get_instance_id_by_pid(request_h req)
{
	int pid;
	int ret;
	const char *pid_str;
	int fd = _request_remove_fd(req);
	bundle *b = _request_get_bundle(req);

	if (b == NULL) {
		_E("Failed to get bundle");
		aul_sock_send_raw_with_fd(fd, APP_GET_INFO_ERROR,
				NULL, 0, AUL_SOCK_NOREPLY);
		return -1;
	}

	pid_str = bundle_get_val(b, AUL_K_PID);
	if (pid_str == NULL || !isdigit(pid_str[0])) {
		_E("Failed to get pid");
		aul_sock_send_raw_with_fd(fd, APP_GET_INFO_ERROR,
				NULL, 0, AUL_SOCK_NOREPLY);
		return -1;
	}

	pid = atoi(pid_str);
	ret = _app_status_get_instance_id_bypid(fd, pid);
	_D("app get instance-id by pid - pid(%d), ret(%d)", pid, ret);

	return ret;
}

static int __dispatch_app_notify_exit(request_h req)
{
	int pid = _request_get_pid(req);
	int ret;
	app_status_h app_status;

	app_status = _app_status_find(pid);
	if (app_status == NULL) {
		_E("pid(%d) is not an application", pid);
		_request_send_result(req, -1);
		return -1;
	}

	ret = _app_status_update_is_exiting(app_status, true);
	_D("[APP_NOTIFY_EXIT] result(%d)", ret);

	return 0;
}

static int __dispatch_app_notify_start(request_h req)
{
	int pid = _request_get_pid(req);
	app_status_h app_status;

	_request_reply_for_pending_request(pid);
	app_status = _app_status_find(pid);
	if (app_status) {
		app_status->socket_exists = true;
		app_status->starting = true;
	}

	_W("[APP_NOTIFY_START] pid(%d)", pid);

	return 0;
}

static request_cmd_dispatch __dispatch_table[] = {
	{
		.cmd = APP_RUNNING_INFO,
		.callback = __dispatch_app_running_info
	},
	{
		.cmd = APP_ALL_RUNNING_INFO,
		.callback = __dispatch_app_all_running_info
	},
	{
		.cmd = APP_IS_RUNNING,
		.callback = __dispatch_app_is_running
	},
	{
		.cmd = APP_GET_PID,
		.callback = __dispatch_app_get_pid
	},
	{
		.cmd = APP_GET_APPID_BYPID,
		.callback = __dispatch_app_get_appid_by_pid
	},
	{
		.cmd = APP_GET_PKGID_BYPID,
		.callback = __dispatch_app_get_pkgid_by_pid
	},
	{
		.cmd = APP_STATUS_UPDATE,
		.callback = __dispatch_app_status_update
	},
	{
		.cmd = APP_GET_STATUS,
		.callback = __dispatch_app_get_status
	},
	{
		.cmd = APP_GET_STATUS_BY_APPID,
		.callback = __dispatch_app_get_status_by_appid
	},
	{
		.cmd = APP_GET_LAST_CALLER_PID,
		.callback = __dispatch_app_get_last_caller_pid
	},
	{
		.cmd = APP_REGISTER_PID,
		.callback = __dispatch_app_register_pid
	},
	{
		.cmd = APP_RUNNING_INSTANCE_INFO,
		.callback = __dispatch_app_running_instance_info
	},
	{
		.cmd = APP_GET_INSTANCE_ID_BYPID,
		.callback = __dispatch_app_get_instance_id_by_pid
	},
	{
		.cmd = APP_NOTIFY_EXIT,
		.callback = __dispatch_app_notify_exit
	},
	{
		.cmd = APP_NOTIFY_START,
		.callback = __dispatch_app_notify_start
	},
};

static int __init_vconf(void)
{
	int r;

	r = vconf_get_int(VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS,
			&limit_bg_uiapps);
	if (r != VCONF_OK)
		_W("Failed to get %s", VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS);

	r = vconf_notify_key_changed(VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS,
			__vconf_cb, NULL);
	if (r != VCONF_OK) {
		_E("Failed to register callback for %s",
				VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS);
		return -1;
	}

	home_appid = vconf_get_str(VCONFKEY_SETAPPL_SELECTED_PACKAGE_NAME);
	r = vconf_notify_key_changed(VCONFKEY_SETAPPL_SELECTED_PACKAGE_NAME,
			__home_appid_vconf_cb, NULL);
	if (r != VCONF_OK) {
		_E("Failed to register callback for %s",
				VCONFKEY_SETAPPL_SELECTED_PACKAGE_NAME);
		vconf_ignore_key_changed(VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS,
				__vconf_cb);
		return -1;
	}

	__vconf.initialized = true;

	return 0;
}

static void __finish_vconf(void)
{
	if (!__vconf.initialized)
		return;

	vconf_ignore_key_changed(VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS,
			__vconf_cb);
	vconf_ignore_key_changed(VCONFKEY_SETAPPL_SELECTED_PACKAGE_NAME,
			__home_appid_vconf_cb);

	__vconf.initialized = false;
}

static gboolean __vconf_init_handler(gpointer data)
{
	static int retry_count;

	retry_count++;
	if (__init_vconf() < 0 && retry_count <= 10) {
		_W("Retry count(%d)", retry_count);
		return G_SOURCE_CONTINUE;
	}

	__vconf.timer = 0;
	return G_SOURCE_REMOVE;
}

int _app_status_init(void)
{
	int ret;

	__wd_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
			NULL, __remove_inotify_watch);
	if (__wd_table == NULL) {
		_E("Out of memory");
		return -1;
	}

	__wh = _inotify_add_watch(PATH_AUL_APPS, IN_CREATE, __dir_monitor_cb, NULL);
	if (!__wh) {
		_E("Failed to add watch(%s)", PATH_AUL_APPS);
		return -1;
	}

	ret = _request_register_cmds(__dispatch_table,
			ARRAY_SIZE(__dispatch_table));
	if (ret < 0) {
		_E("Failed to register cmds");
		return -1;
	}

	__vconf.timer = g_timeout_add(500, __vconf_init_handler, NULL);

	return 0;
}

int _app_status_finish(void)
{
	GSList *iter;
	GSList *iter_next;
	app_status_h app_status;

	GSLIST_FOREACH_SAFE(app_status_list, iter, iter_next) {
		app_status = (app_status_h)iter->data;
		_app_status_cleanup(app_status);
	}

	if (__vconf.timer)
		g_source_remove(__vconf.timer);

	__finish_vconf();

	free(home_appid);

	if (__wh)
		_inotify_rm_watch(__wh);

	if (__wd_table)
		g_hash_table_destroy(__wd_table);

	return 0;
}
