/*
 * Copyright (c) 2017 Samsung Electronics Co., Ltd All Rights Reserved
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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <ctype.h>
#include <glib.h>
#include <aul.h>
#include <bundle_internal.h>
#include <amd.h>

#include "amd_watch.h"

struct watch_info {
	char *appid;
	char *pkgid;
	int pid;
	uid_t uid;
	bool is_faulted;
};

static GList *__restart_list;
static GList *__update_list;

static void __send_dead_signal(const char *appid, pid_t pid, uid_t uid,
		bool is_faulted)
{
	char buf[32];
	bundle *envelope;

	envelope = bundle_create();
	if (envelope == NULL) {
		_E("Out of memory");
		return;
	}

	snprintf(buf, sizeof(buf), "%d", pid);
	bundle_add(envelope, AUL_K_PID, buf);
	bundle_add(envelope, AUL_K_APPID, appid);
	bundle_add(envelope, AUL_K_IS_FAULT, is_faulted ? "true" : "false");

	amd_app_com_send("watch.dead", pid, envelope, uid);
	bundle_free(envelope);
	_D("Send dead signal %s:%d:%u:%d", appid, pid, uid, is_faulted);
}

static void __send_launch_signal(const char *appid, const char *viewer,
		pid_t pid, uid_t uid)
{
	char buf[32];
	bundle *envelope;

	envelope = bundle_create();
	if (envelope == NULL) {
		_E("Out of memory");
		return;
	}

	snprintf(buf, sizeof(buf), "%d", pid);
	bundle_add(envelope, AUL_K_PID, buf);
	bundle_add(envelope, AUL_K_APPID, appid);
	bundle_add(envelope, AUL_K_WIDGET_VIEWER, viewer);

	amd_app_com_send("watch.launch", pid, envelope, uid);
	bundle_free(envelope);
	_D("Send launch signal %s:%d:%u", appid, pid, uid);
}

static void __destroy_watch_info(gpointer data)
{
	struct watch_info *info = (struct watch_info *)data;

	if (info == NULL)
		return;

	if (info->pkgid)
		free(info->pkgid);
	if (info->appid)
		free(info->appid);
	free(info);
}

static struct watch_info *__create_watch_info(const char *appid,
		const char *pkgid, bool is_faulted, pid_t pid, uid_t uid)
{
	struct watch_info *info;

	info = malloc(sizeof(struct watch_info));
	if (info == NULL) {
		_E("Out of memory");
		return NULL;
	}

	info->appid = strdup(appid);
	if (info->appid == NULL) {
		_E("Out of memory");
		free(info);
		return NULL;
	}

	info->pkgid = strdup(pkgid);
	if (info->pkgid == NULL) {
		_E("Out of memory");
		free(info->appid);
		free(info);
		return NULL;
	}

	info->is_faulted = is_faulted;
	info->pid = pid;
	info->uid = uid;

	return info;
}

static void __watch_flush_restart_list(void)
{
	struct watch_info *info;
	GList *iter;

	if (__restart_list == NULL)
		return;

	iter = __restart_list;
	while (iter) {
		info = (struct watch_info *)iter->data;
		__send_dead_signal(info->appid, info->pid, info->uid, true);
		iter = g_list_next(iter);
	}

	g_list_free_full(__restart_list, __destroy_watch_info);
	__restart_list = NULL;
}

static void __watch_flush_update_list(const char *pkgid, uid_t uid)
{
	struct watch_info *info;
	GList *iter;

	if (__update_list == NULL)
		return;

	iter = __update_list;
	while (iter) {
		info = (struct watch_info *)iter->data;
		iter = g_list_next(iter);
		if ((uid < REGULAR_UID_MIN || info->uid == uid) &&
				!strcmp(info->pkgid, pkgid)) {
			__update_list = g_list_remove(__update_list, info);
			__send_dead_signal(info->appid, info->pid, info->uid,
					true);
			__destroy_watch_info(info);
		}
	}
}

static struct watch_info *__find_watch_info(GList *list, const char *appid,
		uid_t uid)
{
	struct watch_info *info;
	GList *iter;

	iter = list;
	while (iter) {
		info = (struct watch_info *)iter->data;
		if (!strcmp(info->appid, appid) && info->uid == uid)
			return info;
		iter = g_list_next(iter);
	}

	return NULL;
}

static int __update_watch_info(const char *appid, const char *pkgid,
		bool is_faulted, pid_t pid, uid_t uid, GList **list)
{
	struct watch_info *info;

	info = __find_watch_info(*list, appid, uid);
	if (info) {
		info->pid = pid;
		info->is_faulted = is_faulted;
		return 0;
	}

	info = __create_watch_info(appid, pkgid, is_faulted, pid, uid);
	if (info == NULL)
		return -1;

	*list = g_list_append(*list, info);

	return 0;
}

static int __on_app_dead(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	amd_app_status_h app_status = arg3;
	int pid = arg1;
	uid_t uid = (uid_t)arg2;
	const char *appid;
	const char *pkgid;
	bool is_faulted;
	int r;
	int app_type;

	if (app_status == NULL)
		return 0;

	app_type = amd_app_status_get_app_type(app_status);
	if (app_type != AMD_AT_WATCH_APP)
		return 0;

	appid = amd_app_status_get_appid(app_status);
	pkgid = amd_app_status_get_pkgid(app_status);
	is_faulted = !amd_app_status_is_exiting(app_status);

	if (amd_util_check_oom()) {
		r = __update_watch_info(appid, pkgid, is_faulted, pid, uid,
				&__restart_list);
		if (r == 0)
			return 0;
	} else if (amd_appinfo_is_pkg_updating(pkgid)) {
		r = __update_watch_info(appid, pkgid, is_faulted, pid, uid,
				&__update_list);
		if (r == 0)
			return 0;
	}

	__send_dead_signal(appid, pid, uid, is_faulted);

	return 0;
}

static int __on_package_update_end(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	uid_t uid = (uid_t)arg1;
	const char *pkgid = (const char *)arg3;

	__watch_flush_update_list(pkgid, uid);

	return 0;
}

static int __on_low_memory_normal(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	__watch_flush_restart_list();
	return 0;
}

static int __on_launch_complete_start(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int pid = arg1;
	amd_appinfo_h ai = (amd_appinfo_h)arg3;
	const char *comptype;
	const char *appid;
	const char *viewer;
	const char *val;
	uid_t uid;

	comptype = amd_appinfo_get_value(ai, AMD_AIT_COMPTYPE);
	if (comptype && !strcmp(comptype, APP_TYPE_WATCH)) {
		appid = bundle_get_val(data, AUL_K_APPID);
		if (appid == NULL)
			return 0;

		viewer = bundle_get_val(data, AUL_K_WIDGET_VIEWER);
		if (viewer == NULL)
			return 0;

		val = bundle_get_val(data, AUL_K_TARGET_UID);
		if (!val || !isdigit(*val))
			return 0;

		uid = strtoul(val, NULL, 10);
		__send_launch_signal(appid, viewer, pid, uid);
	}

	return 0;
}

static int __on_package_update_error(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	uid_t uid = (uid_t)arg1;
	const char *pkgid = (const char *)arg3;

	__watch_flush_update_list(pkgid, uid);

	return 0;
}

EXPORT int AMD_MOD_INIT(void)
{
	_D("watch init");

	amd_noti_listen("main.app_dead", __on_app_dead);
	amd_noti_listen("appinfo.package.update.end", __on_package_update_end);
	amd_noti_listen("util.low_memory.normal", __on_low_memory_normal);
	amd_noti_listen("launch.complete.start", __on_launch_complete_start);
	amd_noti_listen("appinfo.package.update.error",
			__on_package_update_error);

	return 0;
}

EXPORT void AMD_MOD_FINI(void)
{
	_D("watch finish");

	if (__restart_list)
		g_list_free_full(__restart_list, __destroy_watch_info);
	if (__update_list)
		g_list_free_full(__update_list, __destroy_watch_info);
}
