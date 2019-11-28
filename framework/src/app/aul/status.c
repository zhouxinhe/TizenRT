/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <stdio.h>
#include <stdlib.h>

#include <aul.h>
#include <app/bundle.h>
#include <bundle_internal.h>

#include "aul_util.h"
#include "aul_sock.h"
#include "aul_api.h"
#include "launch.h"
#include "aul_app_com.h"

typedef struct _app_status_cb_info_t {
	int (*handler)(int status, void *data);
	void *data;
} app_status_cb_info_t;

struct status_listen_s {
	aul_app_com_connection_h conn;
	app_status_cb callback;
	void *user_data;
};

static int app_status = STATUS_LAUNCHING;
static GList *app_status_cb_list;

API int aul_status_update(int status)
{
	int ret;
	app_status_cb_info_t *cb;
	GList *iter;

	app_status = status;

	ret = aul_sock_send_raw(AUL_UTIL_PID, getuid(), APP_STATUS_UPDATE,
		(unsigned char *)&status, sizeof(status), AUL_SOCK_NOREPLY);

	if (!ret) {
		iter = g_list_first(app_status_cb_list);
		while (iter) {
			cb = (app_status_cb_info_t *)iter->data;
			iter = g_list_next(iter);
			if (cb && cb->handler) {
				if (cb->handler(app_status, cb->data) < 0) {
					app_status_cb_list = g_list_remove(
							app_status_cb_list, cb);
					free(cb);
				}
			}
		}
	}

	return ret;
}

API int aul_app_get_status_bypid(int pid)
{
	return aul_app_get_status_bypid_for_uid(pid, getuid());
}

API int aul_app_get_status_bypid_for_uid(int pid, uid_t uid)
{
	int ret;
	char buf[MAX_PID_STR_BUFSZ];
	bundle *b;

	if (pid == getpid())
		return app_status;

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%d", pid);
	bundle_add(b, AUL_K_PID, buf);
	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_add(b, AUL_K_TARGET_UID, buf);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, uid, APP_GET_STATUS,
			b, AUL_SOCK_NONE);
	bundle_free(b);

	return ret;
}

API int aul_app_get_status(const char *appid)
{
	return aul_app_get_status_for_uid(appid, getuid());
}

API int aul_app_get_status_for_uid(const char *appid, uid_t uid)
{
	int ret;
	bundle *kb;
	char buf[MAX_PID_STR_BUFSZ];

	if (appid == NULL)
		return AUL_R_EINVAL;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_add(kb, AUL_K_APPID, appid);
	bundle_add(kb, AUL_K_TARGET_UID, buf);
	ret = app_send_cmd_for_uid(AUL_UTIL_PID, uid,
			APP_GET_STATUS_BY_APPID, kb);
	bundle_free(kb);

	return ret;
}

API int aul_add_status_local_cb(int (*func)(int status, void *data), void *data)
{
	app_status_cb_info_t *cb;
	GList *iter;

	if (func == NULL)
		return -1;

	iter = g_list_first(app_status_cb_list);
	while (iter) {
		cb = (app_status_cb_info_t *)iter->data;
		if (cb && cb->handler == func && cb->data == data) {
			_D("Already exists");
			return 0;
		}

		iter = g_list_next(iter);
	}

	cb = (app_status_cb_info_t *)malloc(sizeof(app_status_cb_info_t));
	if (cb == NULL) {
		_E("out of memory");
		return -1;
	}

	cb->handler = func;
	cb->data = data;

	app_status_cb_list = g_list_append(app_status_cb_list, cb);

	return 0;
}

API int aul_remove_status_local_cb(int (*func)(int status, void *data), void *data)
{
	app_status_cb_info_t *cb;
	GList *iter;

	iter = g_list_first(app_status_cb_list);
	while (iter) {
		cb = (app_status_cb_info_t *)iter->data;
		iter = g_list_next(iter);
		if (cb && cb->handler == func && cb->data == data) {
			app_status_cb_list = g_list_remove(app_status_cb_list, cb);
			free(cb);
			return 0;
		}
	}

	return -1;
}

API int aul_invoke_status_local_cb(int status)
{
	app_status_cb_info_t *cb;
	GList *iter;

	iter = g_list_first(app_status_cb_list);
	while (iter) {
		cb = (app_status_cb_info_t *)iter->data;
		iter = g_list_next(iter);
		if (cb && cb->handler) {
			if (cb->handler(status, cb->data) < 0) {
				app_status_cb_list = g_list_remove(
						app_status_cb_list, cb);
				free(cb);
			}
		}
	}

	return 0;
}

API int aul_running_list_update(char *appid, char *app_path, char *pid)
{
	int ret;
	bundle *kb;

	kb = bundle_create();

	bundle_add(kb, AUL_K_APPID, appid);
	bundle_add(kb, AUL_K_EXEC, app_path);
	bundle_add(kb, AUL_K_PID, pid);

	ret = app_send_cmd(AUL_UTIL_PID, APP_RUNNING_LIST_UPDATE, kb);

	if (kb != NULL)
			bundle_free(kb);

	return ret;
}

API int aul_set_process_group(int owner_pid, int child_pid)
{
	int ret = -1;
	bundle *kb = NULL;
	char pid_buf[MAX_PID_STR_BUFSZ] = {0,};

	kb = bundle_create();

	if (kb == NULL)
		return -1;

	snprintf(pid_buf, MAX_PID_STR_BUFSZ, "%d", owner_pid);
	bundle_add(kb, AUL_K_OWNER_PID, pid_buf);
	snprintf(pid_buf, MAX_PID_STR_BUFSZ, "%d", child_pid);
	bundle_add(kb, AUL_K_CHILD_PID, pid_buf);
	ret = app_send_cmd(AUL_UTIL_PID, APP_SET_PROCESS_GROUP, kb);
	bundle_free(kb);

	return ret;
}

static int __app_status_event_cb(const char *endpoint, aul_app_com_result_e res,
		bundle *envelope, void *user_data)
{
	struct status_listen_s *listen = (struct status_listen_s *)user_data;
	aul_app_info app_info = { 0, };
	const char *val;
	int context_status;

	if (listen == NULL) {
		_E("Critical error");
		return -1;
	}

	bundle_get_str(envelope, AUL_K_APPID, &app_info.appid);
	if (app_info.appid == NULL) {
		_E("Failed to get application id");
		return -1;
	}

	bundle_get_str(envelope, AUL_K_PKGID, &app_info.pkgid);
	if (app_info.pkgid == NULL) {
		_E("Failed to get package id");
		return -1;
	}

	bundle_get_str(envelope, AUL_K_EXEC, &app_info.app_path);
	if (app_info.app_path == NULL) {
		_E("Failed to get app path");
		return -1;
	}

	bundle_get_str(envelope, AUL_K_INSTANCE_ID, &app_info.instance_id);

	val = bundle_get_val(envelope, AUL_K_PID);
	if (val == NULL) {
		_E("Failed to get pid");
		return -1;
	}
	app_info.pid = atoi(val);

	val = bundle_get_val(envelope, AUL_K_STATUS);
	if (val == NULL) {
		_E("Failed to get status");
		return -1;
	}
	app_info.status = atoi(val);

	val = bundle_get_val(envelope, AUL_K_IS_SUBAPP);
	if (val == NULL) {
		_E("Failed to get is_subapp");
		return -1;
	}
	app_info.is_sub_app = atoi(val);

	val = bundle_get_val(envelope, "__CONTEXT_STATUS__");
	if (val == NULL) {
		_E("Failed to get context status");
		return -1;
	}
	context_status = atoi(val);

	listen->callback(&app_info, context_status, listen->user_data);

	return 0;
}

API int aul_listen_app_status_for_uid(const char *appid, app_status_cb callback,
		void *data, status_listen_h *handle, uid_t uid)
{
	struct status_listen_s *listen;
	char endpoint[128];

	if (appid == NULL || callback == NULL || handle == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	listen = calloc(1, sizeof(struct status_listen_s));
	if (listen == NULL) {
		_E("Out of memory");
		return AUL_R_ERROR;
	}

	if (uid < REGULAR_UID_MIN) {
		snprintf(endpoint, sizeof(endpoint),
				"app_status_event:%s", appid);
	} else {
		snprintf(endpoint, sizeof(endpoint),
				"app_status_event:%s:%d", appid, uid);
	}

	aul_app_com_create(endpoint, NULL, __app_status_event_cb,
			listen, &listen->conn);
	if (listen->conn == NULL) {
		_E("Failed to create app com");
		free(listen);
		return AUL_R_ERROR;
	}

	listen->callback = callback;
	listen->user_data = data;

	*handle = listen;

	return AUL_R_OK;
}

API int aul_listen_app_status(const char *appid, app_status_cb callback,
		void *data, status_listen_h *handle)
{
	return aul_listen_app_status_for_uid(appid, callback, data, handle,
			getuid());
}

API int aul_ignore_app_status(status_listen_h handle)
{
	if (handle == NULL)
		return AUL_R_EINVAL;

	if (handle->conn)
		aul_app_com_leave(handle->conn);
	free(handle);

	return AUL_R_OK;
}

API int aul_notify_exit(void)
{
	return aul_sock_send_raw(AUL_UTIL_PID, getuid(),
			APP_NOTIFY_EXIT, NULL, 0, AUL_SOCK_NOREPLY);
}

API int aul_notify_start(void)
{
	int r;

	r = aul_sock_send_raw(AUL_UTIL_PID, getuid(),
			APP_NOTIFY_START, NULL, 0, AUL_SOCK_NOREPLY);
	return r;
}

API const char *aul_app_status_convert_to_string(int status)
{
	switch (status) {
	case STATUS_LAUNCHING:
		return "STATUS_LAUNCHING";
	case STATUS_CREATED:
		return "STATUS_CREATED";
	case STATUS_FOCUS:
		return "STATUS_FOCUS";
	case STATUS_VISIBLE:
		return "STATUS_VISIBLE";
	case STATUS_BG:
		return "STATUS_BG";
	case STATUS_DYING:
		return "STATUS_DYING";
	case STATUS_HOME:
		return "STATUS_HOME";
	case STATUS_NORESTART:
		return "STATUS_NORESTART";
	case STATUS_SERVICE:
		return "STATUS_SERVICE";
	case STATUS_TERMINATE:
		return "STATUS_TERMINATE";
	default:
		return "Unknown status";
	}
}
