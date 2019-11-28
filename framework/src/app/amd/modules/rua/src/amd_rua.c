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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include <gio/gio.h>
#include <aul.h>
#include <aul_sock.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <rua_internal.h>
#include <rua_stat_internal.h>
#include <dlog.h>

#include "amd.h"
#include "amd_rua.h"

#define PATH_RUN	"/run"
#define FILE_E_IMG	".e-img"
#define PATH_RUN_E_IMG	PATH_RUN "/" FILE_E_IMG
#define MULTI_INSTANCE_SHORTCUT "multi-instance-shortcut"
#define QUERY_KEY_ID "id="
#define QUERY_KEY_ICON "icon="
#define QUERY_KEY_NAME "name="
#define PENDING_REQUEST_TIMEOUT 5000 /* msec */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define AUL_SVC_K_URI		"__APP_SVC_URI__"
#define AUL_SVC_K_LAUNCH_MODE   "__APP_SVC_LAUNCH_MODE__"

#undef LOG_TAG
#define LOG_TAG "AMD_RUA"

struct rua_info_s {
	uid_t uid;
	char *appid;
	char *app_path;
	char *instance_id;
	char *image_path;
	char *temp_path;
};

typedef struct _rua_stat_pkt_t {
	pid_t pid;
	uid_t uid;
	char *stat_tag;
	char *stat_caller;
	char *appid;
	char *instance_id;
	char *instance_name;
	char *icon;
	char *uri;
	gboolean is_group_app;
	char *data;
	int len;
} rua_stat_pkt_t;

struct instance_info {
	char *id;
	char *name;
	char *icon;
	char *uri;
};

static amd_inotify_watch_info_h __dir_create_wh;
static amd_inotify_watch_info_h __img_close_write_wh;
static amd_inotify_watch_info_h __img_create_wh;
static GHashTable *__rua_tbl;
static struct instance_info __inst_info;
static GList *__user_list;

static void __clear_all_imgs(void)
{
	DIR *dp;
	struct dirent *dentry = NULL;
	char buf[PATH_MAX];
	struct stat statbuf;
	int r;

	dp = opendir(PATH_RUN_E_IMG);
	if (dp == NULL)
		return;

	while ((dentry = readdir(dp))) {
		if (!strcmp(dentry->d_name, ".") ||
				!strcmp(dentry->d_name, ".."))
			continue;

		snprintf(buf, sizeof(buf), "%s/%s",
				PATH_RUN_E_IMG, dentry->d_name);
		r = stat(buf, &statbuf);
		if (r == 0) {
			if (S_ISREG(statbuf.st_mode))
				unlink(buf);
		}
	}
	closedir(dp);
}

static bool __is_group_request(bundle *kb, uid_t uid)
{
	const char *str;
	const char *mode;
	const char *appid;
	amd_appinfo_h ai;

	if (kb == NULL)
		return false;

	appid = bundle_get_val(kb, AUL_K_APPID);
	if (appid == NULL)
		return false;

	ai = amd_appinfo_find(uid, appid);
	mode = amd_appinfo_get_value(ai, AMD_AIT_LAUNCH_MODE);
	if (mode != NULL && strcmp(mode, "caller") == 0) {
		str = bundle_get_val(kb, AUL_SVC_K_LAUNCH_MODE);
		if (str != NULL && strcmp(str, "group") == 0)
			return true;
	} else if (mode != NULL && strcmp(mode, "group") == 0) {
		return true;
	}

	return false;
}

static void __free_rua_stat_pkt(void *data)
{
	rua_stat_pkt_t *pkt = data;

	if (pkt == NULL)
		return;

	if (pkt->data)
		free(pkt->data);
	if (pkt->uri)
		free(pkt->uri);
	if (pkt->icon)
		free(pkt->icon);
	if (pkt->instance_name)
		free(pkt->instance_name);
	if (pkt->instance_id)
		free(pkt->instance_id);
	if (pkt->appid)
		free(pkt->appid);
	if (pkt->stat_caller)
		free(pkt->stat_caller);
	if (pkt->stat_tag)
		free(pkt->stat_tag);

	free(pkt);
}

static rua_stat_pkt_t *__create_rua_stat_pkt(amd_request_h req, bundle *kb,
		const char *appid, struct instance_info *info, int pid)
{
	const char *stat_caller;
	const char *stat_tag;
	rua_stat_pkt_t *rua_stat_item;
	int len = amd_request_get_len(req);
	amd_app_status_h app_status;
	amd_appinfo_h app_info;
	const char *instance_id;
	const char *multiple;
	uid_t uid;

	rua_stat_item = calloc(1, sizeof(rua_stat_pkt_t));
	if (rua_stat_item == NULL) {
		LOGE("out of memory");
		return NULL;
	}

	rua_stat_item->pid = pid;

	if (len > 0) {
		rua_stat_item->data = calloc(len + 1, sizeof(char));
		if (rua_stat_item->data == NULL) {
			LOGE("out of memory");
			goto err;
		}
		memcpy(rua_stat_item->data, amd_request_get_raw(req),
				amd_request_get_len(req));
	}
	rua_stat_item->len = len;

	stat_caller = bundle_get_val(kb, AUL_SVC_K_RUA_STAT_CALLER);
	if (stat_caller != NULL) {
		rua_stat_item->stat_caller = strdup(stat_caller);
		if (rua_stat_item->stat_caller == NULL) {
			LOGE("Out of memory");
			goto err;
		}
	}

	stat_tag = bundle_get_val(kb, AUL_SVC_K_RUA_STAT_TAG);
	if (stat_tag != NULL) {
		rua_stat_item->stat_tag = strdup(stat_tag);
		if (rua_stat_item->stat_tag == NULL) {
			LOGE("Out of memory");
			goto err;
		}

	}

	if (appid) {
		rua_stat_item->appid = strdup(appid);
		if (rua_stat_item->appid == NULL) {
			LOGE("Out of memory");
			goto err;
		}
	}

	if (info->id) {
		rua_stat_item->instance_id = strdup(info->id);
		if (rua_stat_item->instance_id == NULL) {
			LOGE("Out of memory");
			goto err;
		}
	} else {
		app_status = amd_app_status_find_by_pid(pid);
		if (!app_status) {
			LOGE("Failed to find app status by pid(%d)", pid);
			goto err;
		}

		uid = amd_app_status_get_uid(app_status);
		app_info = amd_appinfo_find(uid, appid);
		if (!app_info) {
			LOGE("Failed to find app info(%s:%u)", appid, uid);
			goto err;
		}

		multiple = amd_appinfo_get_value(app_info, AMD_AIT_MULTI);
		if (multiple && !strcmp(multiple, "true")) {
			instance_id = amd_app_status_get_instance_id(app_status);
			if (instance_id) {
				rua_stat_item->instance_id = strdup(instance_id);
				if (rua_stat_item->instance_id == NULL) {
					LOGE("Out of memory");
					goto err;
				}
			}
		}
	}

	rua_stat_item->instance_name = strdup(info->name ? info->name : "");
	if (rua_stat_item->instance_name == NULL) {
		LOGE("Out of memory");
		goto err;
	}

	rua_stat_item->icon = strdup(info->icon ? info->icon : "");
	if (rua_stat_item->icon == NULL) {
		LOGE("Out of memory");
		goto err;
	}

	rua_stat_item->uri = strdup(info->uri ? info->uri : "");
	if (rua_stat_item->uri == NULL) {
		LOGE("Out of memory");
		goto err;
	}

	rua_stat_item->uid = amd_request_get_target_uid(req);
	rua_stat_item->is_group_app = __is_group_request(kb,
			rua_stat_item->uid);

	return rua_stat_item;
err:
	__free_rua_stat_pkt(rua_stat_item);

	return NULL;
}

static const char *__rua_get_image_path(int pid)
{
	struct rua_info_s *info;

	if (__rua_tbl == NULL)
		return NULL;

	info = (struct rua_info_s *)g_hash_table_lookup(__rua_tbl,
			GINT_TO_POINTER(pid));
	if (info == NULL)
		return NULL;

	return info->image_path;
}

static gboolean __add_history_handler(gpointer user_data)
{
	struct rua_rec rec = { 0, };
	int ret;
	amd_appinfo_h ai;
	rua_stat_pkt_t *pkt = (rua_stat_pkt_t *)user_data;

	if (!pkt)
		return FALSE;

	if (!pkt->is_group_app) {
		ai = amd_appinfo_find(pkt->uid, pkt->appid);

		rec.pkg_name = pkt->appid;
		rec.app_path = (char *)amd_appinfo_get_value(ai, AMD_AIT_EXEC);

		if (pkt->len > 0)
			rec.arg = pkt->data;

		rec.launch_time = time(NULL);
		rec.instance_id = pkt->instance_id;
		rec.instance_name = pkt->instance_name;
		rec.icon = pkt->icon;
		rec.uri = pkt->uri;
		rec.image = (char *)__rua_get_image_path(pkt->pid);

		SECURE_LOGD("add rua history %s %s",
				rec.pkg_name, rec.app_path);
		ret = rua_usr_db_add_history(&rec, pkt->uid);
		if (ret == -1)
			LOGD("rua add history error");
	}

	if (pkt->stat_caller != NULL && pkt->stat_tag != NULL) {
		SECURE_LOGD("rua_stat_caller: %s, rua_stat_tag: %s",
				pkt->stat_caller, pkt->stat_tag);
		rua_stat_usr_db_update(pkt->stat_caller, pkt->stat_tag,
				pkt->uid);
	}

	__free_rua_stat_pkt(pkt);

	return FALSE;
}

static void __destroy_rua_info(gpointer data)
{
	struct rua_info_s *info = (struct rua_info_s *)data;

	if (info == NULL)
		return;

	if (info->temp_path) {
		unlink(info->temp_path);
		free(info->temp_path);
	}

	if (info->image_path) {
		unlink(info->image_path); /* Delete image file */
		free(info->image_path);
	}

	if (info->instance_id)
		free(info->instance_id);

	if (info->app_path)
		free(info->app_path);

	if (info->appid)
		free(info->appid);

	free(info);
}

static struct rua_info_s *__create_rua_info(const char *appid,
		const char *app_path, const char *instance_id,
		uid_t uid)
{
	struct rua_info_s *info;

	info = calloc(1, sizeof(struct rua_info_s));
	if (info == NULL) {
		LOGE("Out of memory");
		return NULL;
	}

	info->appid = strdup(appid);
	if (info->appid == NULL) {
		LOGE("Out of memory");
		__destroy_rua_info(info);
		return NULL;
	}

	info->app_path = strdup(app_path);
	if (info->app_path == NULL) {
		LOGE("Out of memory");
		__destroy_rua_info(info);
		return NULL;
	}

	if (instance_id) {
		info->instance_id = strdup(instance_id);
		if (info->instance_id == NULL) {
			LOGE("Out of memory");
			__destroy_rua_info(info);
			return NULL;
		}
	}

	info->uid = uid;

	return info;
}

static gboolean __foreach_remove_info(gpointer key, gpointer value,
		gpointer user_data)
{
	struct rua_info_s *info = (struct rua_info_s *)value;
	struct rua_info_s *new_info = (struct rua_info_s *)user_data;

	if (info->uid == new_info->uid &&
			!strcmp(info->appid, new_info->appid)) {
		if (info->instance_id && new_info->instance_id &&
			!strcmp(info->instance_id, new_info->instance_id))
			return TRUE;
		else if (!info->instance_id && !new_info->instance_id)
			return TRUE;
	}

	return FALSE;
}

static int __rua_add_info(int pid, struct instance_info *inst_info)
{
	struct rua_info_s *info;
	amd_app_status_h app_status;
	const char *appid;
	const char *app_path;
	const char *instance_id = NULL;
	amd_appinfo_h ai;
	const char *taskmanage;
	const char *multiple;
	uid_t uid;

	if (__rua_tbl == NULL)
		return 0;

	app_status = amd_app_status_find_by_pid(pid);
	if (app_status == NULL)
		return -1;

	appid = amd_app_status_get_appid(app_status);
	uid = amd_app_status_get_uid(app_status);

	ai = amd_appinfo_find(uid, appid);
	if (!ai)
		return -1;
	taskmanage = amd_appinfo_get_value(ai, AMD_AIT_TASKMANAGE);
	if (!taskmanage || strcmp(taskmanage, "true") != 0)
		return 0;

	app_path = amd_app_status_get_app_path(app_status);
	if (inst_info->id) {
		instance_id = inst_info->id;
	} else {
		multiple = amd_appinfo_get_value(ai, AMD_AIT_MULTI);
		if (multiple && !strcmp(multiple, "true"))
			instance_id = amd_app_status_get_instance_id(app_status);
	}

	info = __create_rua_info(appid, app_path, instance_id, uid);
	if (info == NULL)
		return -1;

	g_hash_table_foreach_remove(__rua_tbl, __foreach_remove_info, info);

	if (g_hash_table_contains(__rua_tbl, GINT_TO_POINTER(pid)))
		g_hash_table_replace(__rua_tbl, GINT_TO_POINTER(pid), info);
	else
		g_hash_table_insert(__rua_tbl, GINT_TO_POINTER(pid), info);

	return 0;
}

static gboolean __foreach_remove_by_uid(gpointer key, gpointer value,
		gpointer data)
{
	struct rua_info_s *info = (struct rua_info_s *)value;
	uid_t uid = GPOINTER_TO_UINT(data);

	if (info->uid == uid)
		return TRUE;

	return FALSE;
}

static gboolean __foreach_remove_by_appid(gpointer key, gpointer value,
		gpointer data)
{
	struct rua_info_s *info = (struct rua_info_s *)value;
	const char *appid = (const char *)data;

	if (strcmp(info->appid, appid) == 0)
		return TRUE;

	return FALSE;
}

static gboolean __foreach_remove_by_app_path(gpointer key, gpointer value,
		gpointer data)
{
	struct rua_info_s *info = (struct rua_info_s *)value;
	const char *app_path = (const char *)data;

	if (strcmp(info->app_path, app_path) == 0)
		return TRUE;

	return FALSE;
}

static gboolean __foreach_remove_by_instance_id(gpointer key, gpointer value,
		gpointer data)
{
	struct rua_info_s *info = (struct rua_info_s *)value;
	const char *instance_id = (const char *)data;

	if (info->instance_id && strcmp(info->instance_id, instance_id) == 0)
		return TRUE;

	return FALSE;
}

static int __delete_rua_info(bundle *b, uid_t uid)
{
	char *appid = NULL;
	char *app_path = NULL;
	char *instance_id = NULL;

	if (b) {
		bundle_get_str(b, AUL_K_RUA_PKGNAME, &appid);
		bundle_get_str(b, AUL_K_RUA_APPPATH, &app_path);
		bundle_get_str(b, AUL_K_RUA_INSTANCE_ID, &instance_id);
	}

	if (appid) {
		g_hash_table_foreach_remove(__rua_tbl,
				__foreach_remove_by_appid, appid);
	} else if (app_path) {
		g_hash_table_foreach_remove(__rua_tbl,
				__foreach_remove_by_app_path, app_path);
	} else if (instance_id) {
		g_hash_table_foreach_remove(__rua_tbl,
				__foreach_remove_by_instance_id, instance_id);
	} else {
		g_hash_table_foreach_remove(__rua_tbl,
				__foreach_remove_by_uid, GUINT_TO_POINTER(uid));
		__clear_all_imgs();
	}

	return 0;
}

static void __update_img_file(const char *img)
{
	int r;
	int pid = -1;
	unsigned int surf = 0;
	int num = -1;
	char buf[PATH_MAX];
	struct rua_info_s *info;
	amd_app_status_h app_status;
	int leader_pid;

	sscanf(img, "win_%d_%u-%d.png", &pid, &surf, &num);
	if (pid <= 0)
		return;

	snprintf(buf, sizeof(buf), "%s/%s", PATH_RUN_E_IMG, img);

	app_status = amd_app_status_find_by_pid(pid);
	leader_pid = amd_app_status_get_leader_pid(app_status);
	if (leader_pid > 0)
		pid = leader_pid;

	info = (struct rua_info_s *)g_hash_table_lookup(__rua_tbl,
			GINT_TO_POINTER(pid));
	if (info == NULL) {
		LOGE("unlink(%s)", buf);
		unlink(buf);
		return;
	}

	if (info->image_path) {
		if (strcmp(info->image_path, buf) == 0)
			return;

		if (info->temp_path &&
				strcmp(info->temp_path, buf) != 0) {
			unlink(info->temp_path);
			free(info->temp_path);
		}

		info->temp_path = info->image_path;
	}

	r = rua_usr_db_update_image(info->appid, info->instance_id,
			buf, info->uid);
	if (r < 0)
		LOGW("Failed to update image path - appid(%s)", info->appid);

	info->image_path = strdup(buf);
	if (info->image_path == NULL)
		LOGE("Out of memory");
}

static void __find_imgs(void)
{
	DIR *dp;
	struct dirent *dentry = NULL;
	char buf[PATH_MAX];
	struct stat statbuf;
	int r;

	dp = opendir(PATH_RUN_E_IMG);
	if (dp == NULL)
		return;

	while ((dentry = readdir(dp))) {
		if (!strcmp(dentry->d_name, ".") ||
				!strcmp(dentry->d_name, ".."))
			continue;

		snprintf(buf, sizeof(buf), "%s/%s",
				PATH_RUN_E_IMG, dentry->d_name);
		r = stat(buf, &statbuf);
		if (r == 0) {
			if (S_ISREG(statbuf.st_mode))
				__update_img_file(buf);
		}
	}
	closedir(dp);
}

static bool __img_on_close_write(const char *event_name, void *data)
{
	if (event_name) {
		__update_img_file(event_name);
		LOGD("%s opened for writing was closed ", event_name);
	}

	return true;
}

static bool __img_on_create(const char *event_name, void *data)
{
	if (event_name)
		LOGD("%s created", event_name);

	return true;
}

static int __monitor_e_img_dir(void)
{
	__img_create_wh = amd_inotify_add_watch(PATH_RUN_E_IMG, IN_CREATE,
			__img_on_create, NULL);
	if (__img_create_wh == NULL)
		LOGE("Failed to add inotify watch");

	__img_close_write_wh = amd_inotify_add_watch(PATH_RUN_E_IMG,
			IN_CLOSE_WRITE, __img_on_close_write, NULL);
	if (__img_close_write_wh == NULL) {
		LOGE("Failed to add inotify watch");
		return -1;
	}

	__find_imgs();

	return 0;
}

static bool __dir_on_create(const char *event_name, void *data)
{
	if (event_name == NULL)
		return true;

	if (strcmp(event_name, FILE_E_IMG) == 0) {
		__monitor_e_img_dir();
		__dir_create_wh = NULL;
		return false;
	}

	return true;
}

static int __dispatch_update_rua_stat(amd_request_h req)
{
	int result;
	char *caller = NULL;
	char *tag = NULL;
	uid_t uid = amd_request_get_target_uid(req);
	bundle *kb = amd_request_get_bundle(req);

	bundle_get_str(kb, AUL_SVC_K_RUA_STAT_CALLER, &caller);
	bundle_get_str(kb, AUL_SVC_K_RUA_STAT_TAG, &tag);
	result = rua_stat_usr_db_update(caller, tag, uid);
	LOGD("rua_stat_usr_db_update - uid(%d), result(%d)", uid, result);
	amd_request_send_result(req, result);

	return 0;
}

static int __dispatch_add_history(amd_request_h req)
{
	int result;
	struct rua_rec rec = {0,};
	char *time_str;
	uid_t uid = amd_request_get_target_uid(req);
	bundle *b = amd_request_get_bundle(req);

	bundle_get_str(b, AUL_K_RUA_PKGNAME, &rec.pkg_name);
	bundle_get_str(b, AUL_K_RUA_APPPATH, &rec.app_path);
	bundle_get_str(b, AUL_K_RUA_ARG, &rec.arg);
	bundle_get_str(b, AUL_K_RUA_TIME, &time_str);
	if (time_str != NULL)
		rec.launch_time = atoi(time_str);
	else
		rec.launch_time = (int)time(NULL);
	bundle_get_str(b, AUL_K_RUA_INSTANCE_ID, &rec.instance_id);
	bundle_get_str(b, AUL_K_RUA_INSTANCE_NAME, &rec.instance_name);
	bundle_get_str(b, AUL_K_RUA_ICON, &rec.icon);
	bundle_get_str(b, AUL_K_RUA_URI, &rec.uri);

	result = rua_usr_db_add_history(&rec, uid);
	LOGD("rua_usr_db_add_history - uid(%d), result(%d)", uid, result);
	amd_request_send_result(req, result);

	return 0;
}

static int __dispatch_remove_history(amd_request_h req)
{
	int result;
	bundle *b = amd_request_get_bundle(req);
	uid_t uid = amd_request_get_target_uid(req);

	result = rua_usr_db_delete_history(b, uid);
	LOGD("rua_usr_db_delete_history - uid(%d), result(%d)", uid, result);
	amd_request_send_result(req, result);
	__delete_rua_info(b, uid);

	return 0;
}

static amd_request_cmd_dispatch __dispatch_table[] = {
	{
		.cmd = APP_UPDATE_RUA_STAT,
		.callback = __dispatch_update_rua_stat
	},
	{
		.cmd = APP_ADD_HISTORY,
		.callback = __dispatch_add_history
	},
	{
		.cmd = APP_REMOVE_HISTORY,
		.callback = __dispatch_remove_history
	},

};

static amd_cynara_checker __cynara_checkers[] = {
	{
		.cmd = APP_UPDATE_RUA_STAT,
		.checker = amd_cynara_simple_checker,
		.data = PRIVILEGE_PLATFORM
	},
	{
		.cmd = APP_ADD_HISTORY,
		.checker = amd_cynara_simple_checker,
		.data = PRIVILEGE_PLATFORM
	},
	{
		.cmd = APP_REMOVE_HISTORY,
		.checker = amd_cynara_simple_checker,
		.data = PRIVILEGE_PLATFORM
	},
};

static bool __user_exists(uid_t uid)
{
	GList *iter;
	uid_t u;

	iter = __user_list;
	while (iter) {
		u = GPOINTER_TO_UINT(iter->data);
		if (u == uid)
			return true;

		iter = g_list_next(iter);
	}

	return false;
}

static int __on_user_init(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	uid_t uid = (uid_t)arg1;

	LOGI("user(%u)", uid);

	if (__user_exists(uid))
		return AMD_NOTI_CONTINUE;

	rua_usr_db_delete_history(NULL, arg1);

	__user_list = g_list_append(__user_list, GUINT_TO_POINTER(uid));

	return AMD_NOTI_CONTINUE;
}

static int __on_user_logout(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	uid_t uid = (uid_t)arg1;

	LOGI("user(%u)", uid);

	if (__user_exists(uid))
		__user_list = g_list_remove(__user_list, GUINT_TO_POINTER(uid));

	if (__rua_tbl == NULL)
		return AMD_NOTI_CONTINUE;

	g_hash_table_foreach_remove(__rua_tbl,
			__foreach_remove_by_uid, GUINT_TO_POINTER(uid));

	return AMD_NOTI_CONTINUE;
}

static void __free_instance_info(struct instance_info *info)
{
	if (info->uri) {
		free(info->uri);
		info->uri = NULL;
	}

	if (info->id) {
		free(info->id);
		info->id = NULL;
	}

	if (info->icon) {
		free(info->icon);
		info->icon = NULL;
	}

	if (info->name) {
		free(info->name);
		info->name = NULL;
	}
}

static char *__get_value_from_query(const char *src, const char *key)
{
	int src_len = strlen(src);
	int key_len = strlen(key);

	if (src_len > key_len) {
		if (strncmp(src, key, key_len) == 0)
			return g_uri_unescape_string(src + key_len, NULL);
	}

	return NULL;
}

static int __get_instance_info(bundle *kb, struct instance_info *info)
{
	const char *uri;
	gchar *scheme;
	gchar *query;
	char *token;
	char *dup_uri;

	uri = bundle_get_val(kb, AUL_SVC_K_URI);
	if (uri == NULL)
		return -1;

	scheme = g_uri_parse_scheme(uri);
	if (scheme == NULL)
		return -1;

	if (strcmp(scheme, MULTI_INSTANCE_SHORTCUT) != 0) {
		g_free(scheme);
		return -1;
	}
	g_free(scheme);

	dup_uri = strdup(uri);
	if (dup_uri == NULL) {
		LOGE("Out of memory");
		return -1;
	}

	info->uri = strdup(uri);
	if (info->uri == NULL) {
		LOGE("Out of memory");
		free(dup_uri);
		return -1;
	}

	query = index(dup_uri, '?');
	if (query == NULL) {
		__free_instance_info(info);
		free(dup_uri);
		return -1;
	}

	token = strtok(query + 1, "&");
	while (token != NULL) {
		if (info->id == NULL)
			info->id = __get_value_from_query(token, QUERY_KEY_ID);
		if (info->icon == NULL) {
			info->icon = __get_value_from_query(token,
					QUERY_KEY_ICON);
		}
		if (info->name == NULL) {
			info->name = __get_value_from_query(token,
					QUERY_KEY_NAME);
		}

		token = strtok(NULL, "&");
	}
	free(dup_uri);

	if (info->id == NULL || info->icon == NULL || info->name == NULL) {
		LOGW("Failed to get instance info");
		__free_instance_info(info);
		return -1;
	}

	return 0;
}

static int __on_launch_starting(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	const char *instance_id;
	bundle *kb = data;

	if (__get_instance_info(kb, &__inst_info) == 0) {
		bundle_del(kb, AUL_K_INSTANCE_ID);
		bundle_add(kb, AUL_K_INSTANCE_ID, __inst_info.id);
		bundle_del(kb, AUL_K_NEW_INSTANCE);
		bundle_add(kb, AUL_K_NEW_INSTANCE, "true");
		LOGD("Multiple instance launch - id(%s), name(%s), icon(%s)",
				__inst_info.id, __inst_info.name, __inst_info.icon);
	} else {
		instance_id = bundle_get_val(kb, AUL_K_INSTANCE_ID);
		if (instance_id) {
			__inst_info.id = strdup(instance_id);
			if (__inst_info.id == NULL)
				LOGW("Out of memory");
			LOGD("Multiple instance launch - id(%s)", __inst_info.id);
		}
	}

	return AMD_NOTI_CONTINUE;
}

static int __on_launch_pending(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	const char *appid;
	bundle *kb;
	int ret = arg1;
	bool bg_launch = arg2;
	amd_request_reply_h reply = (amd_request_reply_h)data;
	rua_stat_pkt_t *rua = NULL;
	amd_request_h req = arg3;

	kb = amd_request_get_bundle(req);
	appid = bundle_get_val(kb, AUL_K_APPID);
	if (!bg_launch && amd_noti_send("rua.save.critical", 0, 0, req, kb) == 0) {
		rua = __create_rua_stat_pkt(req, kb, appid, &__inst_info, ret);
		if (rua && !rua->is_group_app)
			__rua_add_info(ret, &__inst_info);
	}

	__free_instance_info(&__inst_info);
	amd_request_reply_add_extra(reply, "rua", rua, __free_rua_stat_pkt);

	return AMD_NOTI_CONTINUE;
}

static int __on_launch_ending(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	int ret = arg1;
	bool bg_launch = arg2;
	amd_request_h req = arg3;
	rua_stat_pkt_t *rua = NULL;
	const char *appid;
	bundle *kb = data;

	appid = bundle_get_val(kb, AUL_K_APPID);
	if (ret > 0 && !bg_launch &&
			amd_noti_send("rua.save.critical", 0, 0, req, kb) == 0) {
		rua = __create_rua_stat_pkt(req, kb, appid, &__inst_info, ret);
		if (rua == NULL) {
			__free_instance_info(&__inst_info);
			return AMD_NOTI_STOP;
		}
		g_timeout_add(1500, __add_history_handler, rua);
	}
	__free_instance_info(&__inst_info);

	return AMD_NOTI_CONTINUE;
}

static int __reply_foreach_cb(const char *key, void *data)
{
	if (data && key && !strcmp(key, "rua")) {
		g_timeout_add(1500, __add_history_handler, data);
		return 0;
	}

	return -1;
}

static int __on_app_startup(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	int pid = arg1;

	amd_request_reply_foreach_extra(pid, __reply_foreach_cb);

	return AMD_NOTI_CONTINUE;
}

EXPORT int AMD_MOD_INIT(void)
{
	int r;

	LOGD("rua init");

	r = amd_request_register_cmds(__dispatch_table,
			ARRAY_SIZE(__dispatch_table));
	if (r < 0) {
		LOGE("Failed to register cmds");
		return -1;
	}

	r = amd_cynara_register_checkers(__cynara_checkers,
			ARRAY_SIZE(__cynara_checkers));
	if (r < 0) {
		LOGE("Failed to register checkers");
		return -1;
	}

	if (access(PATH_RUN_E_IMG, F_OK) == 0) {
		if (__monitor_e_img_dir() < 0)
			return -1;
	} else {
		__dir_create_wh = amd_inotify_add_watch(PATH_RUN, IN_CREATE,
				__dir_on_create, NULL);
		if (__dir_create_wh == NULL)
			return -1;
	}

	__rua_tbl = g_hash_table_new_full(g_direct_hash, g_direct_equal,
			NULL, __destroy_rua_info);
	if (__rua_tbl == NULL) {
		LOGE("Failed to create rua table");
		return -1;
	}

	amd_noti_listen("request.user_init", __on_user_init);
	amd_noti_listen("login_monitor.user_logout", __on_user_logout);
	amd_noti_listen("launch.app_start.start", __on_launch_starting);
	amd_noti_listen("launch.app_start.pend", __on_launch_pending);
	amd_noti_listen("launch.app_start.end", __on_launch_ending);
	amd_noti_listen("launch.app_startup_signal.end", __on_app_startup);

	return 0;
}

EXPORT void AMD_MOD_FINI(void)
{
	LOGD("rua finish");

	if (__user_list)
		g_list_free(__user_list);

	if (__rua_tbl) {
		g_hash_table_destroy(__rua_tbl);
		__rua_tbl = NULL;
	}

	if (__dir_create_wh)
		amd_inotify_rm_watch(__dir_create_wh);
	if (__img_close_write_wh)
		amd_inotify_rm_watch(__img_close_write_wh);
	if (__img_create_wh)
		amd_inotify_rm_watch(__img_create_wh);
}
