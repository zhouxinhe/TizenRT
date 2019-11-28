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
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <aul.h>
#include <bundle_internal.h>
#include <tzplatform_config.h>

#include "amd.h"
#include "amd_extractor.h"

#define PATH_APP_ROOT tzplatform_getenv(TZ_USER_APP)
#define PATH_GLOBAL_APP_RO_ROOT tzplatform_getenv(TZ_SYS_RO_APP)
#define PATH_GLOBAL_APP_RW_ROOT tzplatform_getenv(TZ_SYS_RW_APP)

typedef char **(_extractor_mountable)(const amd_appinfo_h ai);

static GHashTable *mount_point_hash;

static const char *__get_app_root_path(const amd_appinfo_h ai)
{
	const char *path_app_root;
	const char *global;
	const char *preload;

	preload = amd_appinfo_get_value(ai, AMD_AIT_PRELOAD);
	global = amd_appinfo_get_value(ai, AMD_AIT_GLOBAL);
	if (global && strcmp(global, "true") == 0) {
		if (preload && strcmp(preload, "true") == 0)
			path_app_root = PATH_GLOBAL_APP_RO_ROOT;
		else
			path_app_root = PATH_GLOBAL_APP_RW_ROOT;
	} else {
		path_app_root = PATH_APP_ROOT;
	}

	return path_app_root;
}

static char **__extractor_mountable_get_tep_paths(const amd_appinfo_h ai)
{
	char tep_path[PATH_MAX];
	char **mnt_path;
	const char *pkgid;
	const char *tep_name;

	if (ai == NULL)
		return NULL;

	pkgid = amd_appinfo_get_value(ai, AMD_AIT_PKGID);
	if (pkgid == NULL)
		return NULL;

	tep_name = amd_appinfo_get_value(ai, AMD_AIT_TEP);
	if (tep_name == NULL)
		return NULL;

	mnt_path = (char **)malloc(sizeof(char *) * 2);
	if (mnt_path == NULL) {
		_E("out of memory");
		return NULL;
	}

	mnt_path[1] = strdup(tep_name);
	if (mnt_path[1] == NULL) {
		_E("Out of memory");
		free(mnt_path);
		return NULL;
	}
	snprintf(tep_path, PATH_MAX, "%s/%s/tep/mount",
			__get_app_root_path(ai), pkgid);
	mnt_path[0] = strdup(tep_path);
	if (mnt_path[0] == NULL) {
		_E("Out of memory");
		free(mnt_path[1]);
		free(mnt_path);
		return NULL;
	}

	return mnt_path;
}

static char **__extractor_mountable_get_tpk_paths(const amd_appinfo_h ai)
{
	char mount_point[PATH_MAX];
	char **mnt_path;
	const char *pkgid;
	const char *tpk;

	if (ai == NULL)
		return NULL;

	pkgid = amd_appinfo_get_value(ai, AMD_AIT_PKGID);
	if (pkgid == NULL)
		return NULL;

	tpk = amd_appinfo_get_value(ai, AMD_AIT_MOUNTABLE_PKG);
	if (tpk == NULL)
		return NULL;

	mnt_path = (char **)malloc(sizeof(char *) * 2);
	if (mnt_path == NULL) {
		_E("out of memory");
		return NULL;
	}

	mnt_path[1] = strdup(tpk);
	if (mnt_path[1] == NULL) {
		_E("Out of memory");
		free(mnt_path);
		return NULL;
	}
	snprintf(mount_point, PATH_MAX, "%s/%s/.pkg",
				__get_app_root_path(ai), pkgid);
	mnt_path[0] = strdup(mount_point);
	if (mnt_path[0] == NULL) {
		free(mnt_path[1]);
		free(mnt_path);
		return NULL;
	}

	return mnt_path;
}

static void __free_path(char **path, int cnt)
{
	int i;

	if (path == NULL)
		return;

	for (i = 0; i < cnt; i++) {
		if (path[i])
			free(path[i]);
	}
	free(path);
}

static void __free_set(gpointer data)
{
	g_hash_table_destroy((GHashTable *)data);
}

static void __prepare_map(void)
{
	if (mount_point_hash == NULL) {
		mount_point_hash = g_hash_table_new_full(g_str_hash,
				g_str_equal, free, __free_set);
	}
}

static void __put_mount_path(const amd_appinfo_h ai, const char *str)
{
	const char *appid;
	GHashTable *set;

	__prepare_map();
	set = g_hash_table_lookup(mount_point_hash, str);
	if (set == NULL) {
		set = g_hash_table_new_full(g_str_hash, g_str_equal,
				free, NULL);
		if (set == NULL)
			return;
		g_hash_table_insert(mount_point_hash, strdup(str), set);
	}

	appid = amd_appinfo_get_value(ai, AMD_AIT_NAME);
	g_hash_table_insert(set, strdup(appid), NULL);
}

static bool __is_unmountable(const char *appid, const char *key)
{
	GHashTable *set;

	if (amd_app_status_get_process_cnt(appid) > 1)
		return false;

	__prepare_map();
	set = g_hash_table_lookup(mount_point_hash, key);

	if (set == NULL)
		return false;

	g_hash_table_remove(set, appid);
	if (g_hash_table_size(set) > 0)
		return false;

	return true;
}

static void __extractor_mount(const amd_appinfo_h ai, bundle *kb,
		_extractor_mountable mountable)
{
	int ret;
	const char **array = NULL;
	int len = 0;
	const char *default_array[1] = { NULL };
	char **new_array = NULL;
	int i;
	bool dup = false;
	const char *pkgid = NULL;
	char **mnt_path;

	mnt_path = mountable(ai);
	if (mnt_path == NULL)
		return;

	if (!mnt_path[0] || !mnt_path[1]) {
		__free_path(mnt_path, 2);
		return;
	}

	array = bundle_get_str_array(kb, AUL_K_TEP_PATH, &len);
	if (array == NULL) {
		default_array[0] = mnt_path[0];
		bundle_add_str_array(kb, AUL_K_TEP_PATH,
				     default_array, 1);
	} else {
		for (i = 0; i < len; i++) {
			if (strcmp(mnt_path[0], array[i]) == 0) {
				dup = true;
				break;
			}
		}

		if (!dup) {
			new_array = calloc(len + 1, sizeof(char *));
			if (new_array == NULL) {
				_E("out of memory");
				__free_path(mnt_path, 2);
				return;
			}

			for (i = 0; i < len; i++) {
				new_array[i] = strdup(array[i]);
				if (new_array[i] == NULL) {
					_E("Out of memory");
					__free_path(new_array, i);
					return;
				}
			}
			new_array[len] = strdup(mnt_path[0]);
			if (new_array[len] == NULL) {
				_E("Out of memory");
				__free_path(new_array, len);
				return;
			}
			bundle_del(kb, AUL_K_TEP_PATH);
			bundle_add_str_array(kb, AUL_K_TEP_PATH,
					(const char **)new_array, len + 1);
			__free_path(new_array, len + 1);
		}
	}

	__put_mount_path(ai, mnt_path[0]);
	ret = aul_is_tep_mount_dbus_done(mnt_path[0]);
	if (ret != 1) {
		pkgid = amd_appinfo_get_value(ai, AMD_AIT_PKGID);
		ret = amd_signal_send_tep_mount(mnt_path, pkgid);
		if (ret < 0) {
			_E("dbus error %d", ret);
		} else {
			_D("Mount request was sent %s %s",
					mnt_path[0], mnt_path[1]);
		}
	}

	__free_path(mnt_path, 2);
}

static void __extractor_unmount(int pid, _extractor_mountable mountable)
{
	const char *appid;
	amd_appinfo_h ai;
	int ret;
	char **mnt_path;
	amd_app_status_h app_status;
	uid_t uid;

	app_status = amd_app_status_find_by_pid(pid);
	if (app_status == NULL)
		return;

	uid = amd_app_status_get_uid(app_status);
	appid = amd_app_status_get_appid(app_status);
	if (appid == NULL)
		return;

	ai = amd_appinfo_find(uid, appid);
	if (ai == NULL)
		return;

	mnt_path = mountable(ai);
	if (mnt_path == NULL)
		return;

	if (!__is_unmountable(appid, mnt_path[0]))
		return;

	g_hash_table_remove(mount_point_hash, mnt_path[0]);
	ret = amd_signal_send_tep_unmount(mnt_path[0]);
	if (ret < 0)
		_E("Failed to send unmount: %s", mnt_path[0]);
	else
		_D("Unmount request was sent %s", mnt_path[0]);

	__free_path(mnt_path, 2);
}

static int __on_app_status_cleanup(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	amd_app_status_h app_status = arg3;
	int pid;

	pid = amd_app_status_get_pid(app_status);
	__extractor_unmount(pid, __extractor_mountable_get_tep_paths);
	__extractor_unmount(pid, __extractor_mountable_get_tpk_paths);

	return 0;
}

static int __on_launch_prepared(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	const amd_appinfo_h info = arg3;

	__extractor_mount(info, data, __extractor_mountable_get_tep_paths);
	__extractor_mount(info, data, __extractor_mountable_get_tpk_paths);

	return 0;
}

EXPORT int AMD_MOD_INIT(void)
{
	_D("extractor init");

	amd_noti_listen("app_status.cleanup", __on_app_status_cleanup);
	amd_noti_listen("launch.prepare.end", __on_launch_prepared);

	return 0;
}

EXPORT void AMD_MOD_FINI(void)
{
	_D("extractor fini");
}

