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
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <linux/limits.h>

#include <glib.h>
#include <aul.h>
#include <aul_svc.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <tzplatform_config.h>
#include <security-manager.h>

#include "amd.h"
#include "amd_share.h"

#define LEGACY_APP_PATH "/opt/usr/apps/"
#define AUL_SVC_K_URI       "__APP_SVC_URI__"

typedef struct _shared_info_t {
	char *owner_appid;
	private_sharing_req *handle;
} shared_info_t;

struct shared_info_main_s {
	char *appid;
	uid_t uid;
	shared_info_t *shared_info;
};

typedef struct shared_info_main_s *shared_info_h;

static shared_info_h __cur_shared_info;
static int __temporary_permission_destroy(shared_info_h handle);

static int __can_share(const char *path, const char *pkgid, uid_t uid)
{
	struct stat path_stat;
	char buf[PATH_MAX];

	if (stat(path, &path_stat) != 0) {
		LOGE("failed to stat file to share (%s, %d)", path, errno);
		return -1;
	}

	if (!S_ISREG(path_stat.st_mode)) {
		LOGE("file is not a regular file (%s)", path);
		return -1;
	}

	tzplatform_set_user(uid);
	snprintf(buf, sizeof(buf), "%s/%s/data/",
			tzplatform_getenv(TZ_USER_APP), pkgid);
	tzplatform_reset_user();

	if (strncmp(path, buf, strlen(buf)) != 0) {
		SECURE_LOGD("file is not in app's data directory (%s)", path);
		return -1;
	}

	return 0;
}

static int __get_owner_pid(int caller_pid, bundle *kb)
{
	char *org_caller = NULL;
	const char *appid;
	int org_caller_pid;
	amd_app_status_h app_status;
	int ret;

	ret = bundle_get_str(kb, AUL_K_ORG_CALLER_PID, &org_caller);
	if (ret != BUNDLE_ERROR_NONE)
		return caller_pid;

	org_caller_pid = atoi(org_caller);
	app_status = amd_app_status_find_by_pid(caller_pid);
	appid = amd_app_status_get_appid(app_status);
	if (appid && (strcmp(APP_SELECTOR, appid) == 0 ||
			strcmp(SHARE_PANEL, appid) == 0))
		caller_pid = org_caller_pid;

	return caller_pid;
}

static const char *__get_owner_appid(int caller_pid, bundle *kb)
{
	const char *owner_appid;
	int owner_pid = -1;
	amd_app_status_h app_status;

	owner_pid = __get_owner_pid(caller_pid, kb);
	owner_pid = getpgid(owner_pid); /* for webapp */
	app_status = amd_app_status_find_by_pid(owner_pid);
	owner_appid = amd_app_status_get_appid(app_status);

	return owner_appid;
}

static shared_info_h __new_shared_info_handle(const char *appid, uid_t uid,
		const char *owner_appid)
{
	shared_info_h h;
	int ret;

	h = malloc(sizeof(struct shared_info_main_s));
	if (h == NULL) {
		LOGE("Out of memory");
		return NULL;
	}

	h->shared_info = malloc(sizeof(shared_info_t));
	if (h->shared_info == NULL) {
		LOGE("Out of memory");
		free(h);
		return NULL;
	}

	ret = security_manager_private_sharing_req_new(&h->shared_info->handle);
	if (ret != SECURITY_MANAGER_SUCCESS) {
		LOGE("Failed to create private sharing request handle");
		free(h->shared_info);
		free(h);
		return NULL;
	}

	h->shared_info->owner_appid = strdup(owner_appid);
	if (h->shared_info->owner_appid == NULL) {
		LOGE("Out of memory");
		security_manager_private_sharing_req_free(
				h->shared_info->handle);
		free(h->shared_info);
		free(h);
		return NULL;
	}

	h->appid = strdup(appid);
	if (h->appid == NULL) {
		LOGE("Out of memory");
		free(h->shared_info->owner_appid);
		security_manager_private_sharing_req_free(
				h->shared_info->handle);
		free(h->shared_info);
		free(h);
		return NULL;
	}
	h->uid = uid;

	return h;
}

static char *__convert_legacy_path(const char *path, uid_t uid)
{
	char buf[PATH_MAX];
	int len = strlen(LEGACY_APP_PATH);

	if (strncmp(LEGACY_APP_PATH, path, len) == 0) {
		tzplatform_set_user(uid);
		snprintf(buf, sizeof(buf), "%s/%s",
			tzplatform_getenv(TZ_USER_APP), &path[len]);
		tzplatform_reset_user();

		return strdup(buf);
	}

	return strdup(path);
}

static GList *__add_valid_uri(GList *paths, int caller_pid, const char *appid,
		const char *owner_appid, bundle *kb, uid_t uid)
{
	char *path = NULL;
	const char *pkgid;
	amd_appinfo_h ai;
	int ret;

	ret = bundle_get_str(kb, AUL_SVC_K_URI, &path);
	if (ret != BUNDLE_ERROR_NONE)
		return paths;

	if (!path) {
		LOGD("path was null");
		return paths;
	}

	if (strncmp(path, "file://", 7) == 0) {
		path = &path[7];
	} else {
		LOGE("file wasn't started with file://");
		return paths;
	}

	ai = amd_appinfo_find(uid, owner_appid);
	pkgid = amd_appinfo_get_value(ai, AMD_AIT_PKGID);

	path = __convert_legacy_path(path, uid);
	if (__can_share(path, pkgid, uid) != 0) {
		LOGE("__can_share() returned an error");
		free(path);
		return paths;
	}
	paths = g_list_append(paths, path);

	return paths;
}

static GList *__add_valid_key_for_data_selected(GList *paths, int caller_pid,
		const char *appid, const char *owner_appid, bundle *kb,
		uid_t uid)
{
	int i;
	int len = 0;
	const char **path_array = NULL;
	char *path_str;
	int type = bundle_get_type(kb, AUL_SVC_DATA_SELECTED);
	const char *pkgid = NULL;
	amd_appinfo_h ai = NULL;

	if (type != BUNDLE_TYPE_STR_ARRAY)
		return paths;

	path_array = bundle_get_str_array(kb, AUL_SVC_DATA_SELECTED, &len);
	if (!path_array || len <= 0) {
		LOGE("path_array was null");
		return paths;
	}

	ai = amd_appinfo_find(uid, owner_appid);
	if (ai == NULL) {
		LOGE("appinfo is NULL");
		return paths;
	}
	pkgid = amd_appinfo_get_value(ai, AMD_AIT_PKGID);
	if (pkgid == NULL) {
		LOGE("pkgid was null");
		return paths;
	}

	for (i = 0; i < len; i++) {
		path_str = __convert_legacy_path(path_array[i], uid);
		if (__can_share(path_str, pkgid, uid) == 0)
			paths = g_list_append(paths, path_str);
		else
			free(path_str);
	}

	return paths;
}

static GList *__add_valid_key_for_data_path(GList *paths, int caller_pid,
		const char *appid, const char *owner_appid, bundle *kb,
		uid_t uid)
{
	int type = bundle_get_type(kb, AUL_SVC_DATA_PATH);
	char *path = NULL;
	const char **path_array = NULL;
	int len;
	int i;
	const char *pkgid = NULL;
	amd_appinfo_h ai = NULL;
	char *path_str;

	switch (type) {
	case BUNDLE_TYPE_STR:
		bundle_get_str(kb, AUL_SVC_DATA_PATH, &path);
		if (!path) {
			LOGE("path was null");
			break;
		}

		ai = amd_appinfo_find(uid, owner_appid);
		pkgid = amd_appinfo_get_value(ai, AMD_AIT_PKGID);
		if (pkgid == NULL) {
			LOGE("pkgid was null");
			break;
		}

		path = __convert_legacy_path(path, uid);
		if (__can_share(path, pkgid, uid) != 0) {
			LOGE("__can_share() returned an error");
			free(path);
			break;
		}

		paths = g_list_append(paths, path);
		break;
	case BUNDLE_TYPE_STR_ARRAY:
		path_array = bundle_get_str_array(kb, AUL_SVC_DATA_PATH, &len);
		if (!path_array || len <= 0) {
			LOGE("path_array was null");
			break;
		}

		ai = amd_appinfo_find(uid, owner_appid);
		pkgid = amd_appinfo_get_value(ai, AMD_AIT_PKGID);
		if (pkgid == NULL) {
			LOGE("pkgid was null");
			break;
		}

		for (i = 0; i < len; i++) {
			path_str = __convert_legacy_path(path_array[i], uid);
			if (__can_share(path_str, pkgid, uid) == 0)
				paths = g_list_append(paths, path_str);
			else
				free(path_str);
		}

		break;
	}

	return paths;
}

static char **__convert_list_to_array(GList *list)
{
	int len;
	int i = 0;
	char **array;

	if (list == NULL)
		return NULL;

	len = g_list_length(list);
	if (len == 0)
		return NULL;

	array = (char **)g_malloc0(sizeof(char *) * (len + 1));
	if (array == NULL) {
		LOGE("out of memory");
		return NULL;
	}

	while (list) {
		array[i] = g_strdup(list->data);
		if (array[i] == NULL) {
			LOGE("Out of memory");
			g_strfreev(array);
			return NULL;
		}

		list = g_list_next(list);
		i++;
	}
	array[len] = NULL;

	return array;
}

static int __destroy_status(amd_app_status_h status)
{
	GList *list;
	GList *i;
	shared_info_t *shared_info;

	if (!status)
		return -1;

	list = amd_app_status_get_extra(status, "share");
	if (!list)
		return -1;

	i = list;
	while (i) {
		shared_info = (shared_info_t *)i->data;
		if (shared_info) {
			if (shared_info->owner_appid)
				free(shared_info->owner_appid);
			free(shared_info);
		}
		i = g_list_next(i);
	}

	g_list_free(list);
	amd_app_status_remove_extra(status, "share");

	return 0;
}

static shared_info_h __temporary_permission_create(int caller_pid, const char *appid,
		bundle *kb, uid_t uid)
{
	char **path_array = NULL;
	int len;
	const char *owner_appid = NULL;
	GList *paths = NULL;
	shared_info_h h = NULL;
	int r;

	owner_appid = __get_owner_appid(caller_pid, kb);
	paths = __add_valid_key_for_data_path(paths, caller_pid, appid,
			owner_appid, kb, uid);
	paths = __add_valid_key_for_data_selected(paths, caller_pid, appid,
			owner_appid, kb, uid);
	paths = __add_valid_uri(paths, caller_pid, appid, owner_appid, kb, uid);
	if (!paths || !owner_appid)
		goto clear;

	LOGD("grant permission %s : %s", owner_appid, appid);

	h = __new_shared_info_handle(appid, uid, owner_appid);
	if (h == NULL)
		goto clear;

	len = g_list_length(paths);
	path_array = __convert_list_to_array(paths);
	if (path_array == NULL)
		goto clear;

	r = security_manager_private_sharing_req_set_owner_appid(
			h->shared_info->handle, owner_appid);
	if (r != SECURITY_MANAGER_SUCCESS)
		LOGE("Failed to set owner appid(%s) %d", owner_appid, r);

	r = security_manager_private_sharing_req_set_target_appid(
			h->shared_info->handle, appid);
	if (r != SECURITY_MANAGER_SUCCESS)
		LOGE("Failed to set target appid(%s) %d", appid, r);

	r = security_manager_private_sharing_req_add_paths(
			h->shared_info->handle, (const char **)path_array, len);
	if (r != SECURITY_MANAGER_SUCCESS)
		LOGE("Failed to add paths %d", r);

	LOGD("security_manager_private_sharing_apply ++");
	r = security_manager_private_sharing_apply(h->shared_info->handle);
	LOGD("security_manager_private_sharing_apply --");
	if (r != SECURITY_MANAGER_SUCCESS) {
		LOGE("Failed to apply private sharing %d", r);
		__temporary_permission_destroy(h);
		h = NULL;
	}

clear:
	if (paths)
		g_list_free_full(paths, free);

	if (path_array)
		g_strfreev(path_array);

	return h;
}

static int __temporary_permission_apply(int pid, uid_t uid, shared_info_h handle)
{
	amd_app_status_h status;
	GList *list;

	if (handle == NULL)
		return -1;

	status = amd_app_status_find_by_pid(pid);
	if (status == NULL)
		return -1;

	list = amd_app_status_get_extra(status, "share");
	list = g_list_append(list, handle->shared_info);
	amd_app_status_set_extra(status, "share", list);
	handle->shared_info = NULL;

	return 0;
}

static int __temporary_permission_destroy(shared_info_h handle)
{
	int r;

	if (handle == NULL)
		return -1;

	if (handle->shared_info) { /* back out */
		LOGD("revoke permission %s : %s",
				handle->shared_info->owner_appid,
				handle->appid);
		r = security_manager_private_sharing_drop(
				handle->shared_info->handle);
		if (r != SECURITY_MANAGER_SUCCESS)
			LOGE("revoke error %d", r);

		security_manager_private_sharing_req_free(
				handle->shared_info->handle);
		free(handle->shared_info->owner_appid);
	}

	free(handle->appid);
	free(handle);

	return 0;
}

static int __temporary_permission_drop(int pid, uid_t uid)
{
	int r;
	shared_info_t *sit;
	amd_app_status_h app_status;
	GList *list;

	app_status = amd_app_status_find_by_pid(pid);
	if (app_status == NULL)
		return -1;

	list = amd_app_status_get_extra(app_status, "share");
	if (!list) {
		LOGD("list was null");
		return -1;
	}

	while (list) {
		sit = (shared_info_t *)list->data;
		LOGD("revoke permission %s : %d", sit->owner_appid, pid);
		r = security_manager_private_sharing_drop(sit->handle);
		if (r != SECURITY_MANAGER_SUCCESS)
			LOGE("revoke error %d", r);
		security_manager_private_sharing_req_free(sit->handle);
		list = g_list_next(list);
	}

	return __destroy_status(app_status);
}

static int  __on_app_result_start(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	char *appid = arg3;
	int pid = arg1;
	uid_t uid = arg2;

	if (appid) {
		__cur_shared_info = __temporary_permission_create(pid, appid, data, uid);
		if (__cur_shared_info == NULL)
			LOGD("No sharable path : %d %s", pid, appid);
	}

	return 0;
}

static int  __on_app_result_end(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int pid = arg1;
	uid_t uid = arg2;
	int res = GPOINTER_TO_INT(arg3);
	int ret;

	if (__cur_shared_info) {
		if (res >= 0) {
			ret = __temporary_permission_apply(pid, uid, __cur_shared_info);
			if (ret != 0) {
				LOGD("Couldn't apply temporary permission: %d",
						ret);
			}
		}
		__temporary_permission_destroy(__cur_shared_info);
		__cur_shared_info = NULL;
	}

	return 0;
}

static int __on_launch_prepare_end(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int caller_pid = arg1;
	uid_t target_uid = arg2;
	const char *appid;
	amd_appinfo_h ai = arg3;
	amd_app_status_h status;
	const char *caller_appid;

	appid = amd_appinfo_get_value(ai, AMD_AIT_NAME);
	status = amd_app_status_find_by_pid(caller_pid);
	caller_appid = amd_app_status_get_appid(status);

	if (caller_appid) {
		__cur_shared_info = __temporary_permission_create(caller_pid,
				appid, data, target_uid);
		if (__cur_shared_info == NULL)
			LOGW("No sharable path: %d %s", caller_pid, appid);
	}

	return 0;
}

static int __on_launch_complete_end(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int pid = arg1;
	uid_t target_uid = arg2;
	int ret;

	if (__cur_shared_info) {
		ret = __temporary_permission_apply(pid, target_uid,
				__cur_shared_info);
		if (ret < 0)
			LOGD("Couldn't apply temporary permission: %d", ret);

		__temporary_permission_destroy(__cur_shared_info);
		__cur_shared_info = NULL;
	}

	return 0;
}

static int __on_launch_cancel(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	if (__cur_shared_info) {
		__temporary_permission_destroy(__cur_shared_info);
		__cur_shared_info = NULL;
	}

	return 0;
}

static int __on_app_status_destroy(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	amd_app_status_h status = arg3;

	return __destroy_status(status);
}

static int __on_app_status_cleanup(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int pid = arg1;
	uid_t uid = arg2;

	__temporary_permission_drop(pid, uid);

	return 0;
}

EXPORT int AMD_MOD_INIT(void)
{
	LOGD("share init");
	amd_noti_listen("launch.app_result.start", __on_app_result_start);
	amd_noti_listen("launch.app_result.end", __on_app_result_end);
	amd_noti_listen("launch.prepare.end", __on_launch_prepare_end);
	amd_noti_listen("launch.complete.end", __on_launch_complete_end);
	amd_noti_listen("launch.do_starting_app.cancel", __on_launch_cancel);
	amd_noti_listen("launch.do_starting_app.relaunch.cancel", __on_launch_cancel);
	amd_noti_listen("app_status.cleanup", __on_app_status_cleanup);
	amd_noti_listen("app_group.do_recycle.end", __on_app_status_cleanup);
	amd_noti_listen("app_status.destroy", __on_app_status_destroy);

	return 0;
}

EXPORT void AMD_MOD_FINI(void)
{
	LOGD("share finish");
}

