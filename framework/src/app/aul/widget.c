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
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glib.h>
#include <bundle.h>
#include <bundle_internal.h>

#include "aul.h"
#include "aul_util.h"
#include "aul_sock.h"
#include "aul_cmd.h"
#include "aul_error.h"
#include "launch.h"
#include "aul_widget.h"

struct aul_widget_info_s {
	char *widget_id;
	char *instance_id;
	char *app_id;
	char *package_id;
	char *app_path;
	unsigned int surf;
	pid_t pid;
};

struct widget_cb_info {
	aul_widget_info_cb callback;
	void *user_data;
};

#define WIDGET_LOG_BUFFER_SIZE 10000
#define WIDGET_LOG_BUFFER_STRING_SIZE 256

static int __log_index;
static int __log_fd;
static bool __log_init = false;

static int __init_log(void)
{
	int offset;
	char buffer[256] = {0, };
	char caller[255] = {0, };
	int ret;

	ret = aul_app_get_appid_bypid(getpid(), caller, sizeof(caller));
	if (ret != AUL_R_OK) {
		_E("Failed to get appid by pid(%d)", getpid());
		return -1;
	}

	snprintf(buffer, sizeof(buffer),
			"/run/aul/log/widget/%d/widget_%s.log", getuid(), caller);
	__log_fd = open(buffer, O_CREAT | O_WRONLY, 0644);
	if (__log_fd < 0) {
		_E("Failed to open %s - %d", buffer, errno);
		return -1;
	}

	offset = lseek(__log_fd, 0, SEEK_END);
	if (offset != 0) {
		__log_index = (int)(offset / WIDGET_LOG_BUFFER_STRING_SIZE);
		if (__log_index >= WIDGET_LOG_BUFFER_SIZE) {
			__log_index = 0;
			lseek(__log_fd, 0, SEEK_SET);
		}
	}
	__log_init = true;

	return 0;
}

API int aul_widget_write_log(const char *tag, const char *format, ...)
{
	int ret;
	int offset;
	time_t now;
	char time_buf[32] = {0,};
	char format_buffer[WIDGET_LOG_BUFFER_STRING_SIZE];
	char buffer[WIDGET_LOG_BUFFER_STRING_SIZE];
	va_list ap;

	if (!__log_init)
		__init_log();

	if (__log_fd < 0) {
		_E("Invalid file descriptor");
		return -1;
	}

	time(&now);
	ctime_r(&now, time_buf);
	if (__log_index != 0)
		offset = lseek(__log_fd, 0, SEEK_CUR);
	else
		offset = lseek(__log_fd, 0, SEEK_SET);

	if (offset == -1)
		_E("error in lseek: %d", errno);


	va_start(ap, format);
	vsnprintf(format_buffer, sizeof(format_buffer), format, ap);
	va_end(ap);

	snprintf(buffer, sizeof(buffer), "[%-6d][%-5d] %-15s %-50s %s",
			getpid(), __log_index, tag, format_buffer, time_buf);

	ret = write(__log_fd, buffer, strlen(buffer));
	if (ret < 0) {
		_E("Cannot write the amd log: %d", ret);
		return -1;
	}

	if (++__log_index >= WIDGET_LOG_BUFFER_SIZE)
		__log_index = 0;

	return 0;
}

static const char *__to_appid(const char *widget_id)
{
	const char *appid;
	appid = g_strstr_len(widget_id, strlen(widget_id), "@") + 1;
	if (appid != (const char *)1) {
		if (appid > widget_id + (sizeof(char) * strlen(widget_id)))
			appid = (char *)widget_id;
	} else {
		appid = (char *)widget_id;
	}

	return appid;
}

API int aul_widget_instance_add(const char *widget_id, const char *instance_id)
{
	int ret;
	bundle *kb;

	if (widget_id == NULL || instance_id == NULL)
		return AUL_R_EINVAL;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	bundle_add_str(kb, AUL_K_WIDGET_ID, widget_id);
	bundle_add_str(kb, AUL_K_WIDGET_INSTANCE_ID, instance_id);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(), WIDGET_ADD, kb,
		AUL_SOCK_NONE);

	bundle_free(kb);
	if (ret < 0)
		return aul_error_convert(ret);

	return AUL_R_OK;
}

API int aul_widget_instance_del(const char *widget_id, const char *instance_id)
{
	int ret;
	bundle *kb;

	if (widget_id == NULL || instance_id == NULL)
		return AUL_R_EINVAL;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	bundle_add_str(kb, AUL_K_WIDGET_ID, widget_id);
	bundle_add_str(kb, AUL_K_WIDGET_INSTANCE_ID, instance_id);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(), WIDGET_DEL, kb,
		AUL_SOCK_NONE);

	bundle_free(kb);
	if (ret < 0)
		return aul_error_convert(ret);

	return AUL_R_OK;
}

struct __cb_data {
	aul_widget_instance_foreach_cb cb;
	void *data;
};

static void __foreach_cb(const char *key, const int type,
		const bundle_keyval_t *kv, void *user_data)
{
	struct __cb_data *cb_data = (struct __cb_data *)user_data;

	cb_data->cb(key, cb_data->data);
}

API int aul_widget_instance_foreach(const char *widget_id,
		aul_widget_instance_foreach_cb cb, void *data)
{
	int ret;
	int fd;
	bundle *kb;
	app_pkt_t *pkt = NULL;
	bundle *list_kb = NULL;
	struct __cb_data cb_data;

	if (widget_id == NULL)
		return AUL_R_EINVAL;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	bundle_add_str(kb, AUL_K_APPID, __to_appid(widget_id));
	bundle_add_str(kb, AUL_K_WIDGET_ID, widget_id);

	fd = aul_sock_send_bundle(AUL_UTIL_PID, getuid(), WIDGET_LIST, kb,
		AUL_SOCK_ASYNC);

	if (fd > 0) {
		ret = aul_sock_recv_reply_pkt(fd, &pkt);
		if (ret < 0 || pkt == NULL) {
			_E("failed to get instance list of %s", widget_id);
		} else {
			list_kb = bundle_decode(pkt->data, pkt->len);
			if (list_kb) {
				cb_data.cb = cb;
				cb_data.data = data;
				bundle_foreach(list_kb, __foreach_cb, &cb_data);
				bundle_free(list_kb);
			}
		}
	} else {
		ret = fd;
	}

	if (pkt)
		free(pkt);

	bundle_free(kb);

	if (ret < 0)
		return aul_error_convert(ret);

	return AUL_R_OK;
}

API int aul_widget_instance_update(const char *widget_id,
		const char *instance_id, bundle *param)
{
	int ret;
	bundle *kb = param;
	const char *appid;

	if (widget_id == NULL)
		return AUL_R_EINVAL;

	if (kb == NULL)
		kb = bundle_create();

	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	appid = __to_appid(widget_id);

	bundle_add_str(kb, AUL_K_WIDGET_ID, widget_id);

	if (instance_id)
		bundle_add_str(kb, AUL_K_WIDGET_INSTANCE_ID, instance_id);

	ret = app_request_to_launchpad_for_uid(WIDGET_UPDATE, appid, kb,
			getuid());

	if (param == NULL)
		bundle_free(kb);

	return ret;
}

API int aul_widget_instance_get_content(const char *widget_id,
		const char *instance_id, char **content)
{
	int ret;
	bundle *kb;
	int fd[2] = { 0, };
	app_pkt_t *pkt = NULL;

	if (widget_id == NULL || instance_id == NULL || content == NULL)
		return AUL_R_EINVAL;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	bundle_add_str(kb, AUL_K_APPID, __to_appid(widget_id));
	bundle_add_str(kb, AUL_K_WIDGET_ID, widget_id);
	bundle_add_str(kb, AUL_K_WIDGET_INSTANCE_ID, instance_id);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(), WIDGET_GET_CONTENT,
			kb, AUL_SOCK_ASYNC);
	if (ret > 0) {
		ret = aul_sock_recv_reply_sock_fd(ret, &fd, 1);
		if (ret == 0) {
			ret = aul_sock_recv_reply_pkt(fd[0], &pkt);
			if (ret == 0 && pkt && pkt->cmd == 0) {
				*content = strdup((const char *)pkt->data);
				_D("recieved content: %s", *content);
			} else {
				if (pkt)
					ret = pkt->cmd;

				_E("failed to get content");
			}
		} else {
			_E("failed to get socket fd:%d", ret);
		}
	}

	bundle_free(kb);

	if (pkt)
		free(pkt);
	if (ret < 0)
		ret = aul_error_convert(ret);

	return ret;
}

API int aul_widget_instance_count(const char *widget_id)
{
	int ret;
	bundle *kb;

	if (widget_id == NULL)
		return AUL_R_EINVAL;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	bundle_add_str(kb, AUL_K_WIDGET_ID, widget_id);
	ret = app_send_cmd(AUL_UTIL_PID, WIDGET_COUNT, kb);
	bundle_free(kb);

	return ret;
}

static void __foreach_widget_info(app_pkt_t *pkt, void *user_data)
{
	struct widget_cb_info *cb_info = (struct widget_cb_info *)user_data;
	struct aul_widget_info_s info = { 0, };
	bundle *b = NULL;
	const char *val;

	if (pkt == NULL || cb_info == NULL) {
		_E("Invalid parameter");
		return;
	}

	if (pkt->cmd == APP_GET_INFO_ERROR) {
		_E("Failed to get widget info");
		return;
	}

	if (pkt->opt & AUL_SOCK_BUNDLE)
		b = bundle_decode(pkt->data, pkt->len);

	if (b == NULL)
		return;

	bundle_get_str(b, AUL_K_WIDGET_ID, &info.widget_id);
	if (info.widget_id == NULL) {
		bundle_free(b);
		return;
	}

	bundle_get_str(b, AUL_K_WIDGET_INSTANCE_ID, &info.instance_id);
	if (info.instance_id == NULL) {
		bundle_free(b);
		return;
	}

	bundle_get_str(b, AUL_K_APPID, &info.app_id);
	if (info.app_id == NULL) {
		bundle_free(b);
		return;
	}

	bundle_get_str(b, AUL_K_PKGID, &info.package_id);
	if (info.package_id == NULL) {
		bundle_free(b);
		return;
	}

	bundle_get_str(b, AUL_K_EXEC, &info.app_path);
	if (info.app_path == NULL) {
		bundle_free(b);
		return;
	}

	val = bundle_get_val(b, AUL_K_WID);
	if (val && isdigit(*val))
		info.surf = strtoul(val, NULL, 10);

	val = bundle_get_val(b, AUL_K_PID);
	if (val && isdigit(*val))
		info.pid = atoi(val);

	cb_info->callback(&info, cb_info->user_data);

	bundle_free(b);
}

API int aul_widget_info_foreach_for_uid(aul_widget_info_cb callback,
		void *user_data, uid_t uid)
{
	struct widget_cb_info cb_info = {callback, user_data};
	char buf[MAX_PID_STR_BUFSZ];
	bundle *b;
	int fd;
	int r;

	if (callback == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	b = bundle_create();
	if (b == NULL) {
		_E("Out of memory");
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%u", uid);
	r = bundle_add_str(b, AUL_K_TARGET_UID, buf);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add target uid(%u)", uid);
		bundle_free(b);
		return AUL_R_ERROR;
	}

	fd = aul_sock_send_bundle(AUL_UTIL_PID, uid, WIDGET_RUNNING_INFO,
			b, AUL_SOCK_ASYNC);
	if (fd < 0) {
		bundle_free(b);
		return aul_error_convert(fd);
	}
	bundle_free(b);

	r = aul_sock_recv_pkt_with_cb(fd, __foreach_widget_info, &cb_info);
	if (r < 0)
		return aul_error_convert(r);

	return AUL_R_OK;
}

API int aul_widget_info_foreach(aul_widget_info_cb callback, void *user_data)
{
	return aul_widget_info_foreach_for_uid(callback, user_data, getuid());
}

API int aul_widget_info_get_pid(aul_widget_info_h info, pid_t *pid)
{
	if (info == NULL || pid == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	*pid = info->pid;

	return AUL_R_OK;
}

API int aul_widget_info_get_surface_id(aul_widget_info_h info,
		unsigned int *surf)
{
	if (info == NULL || surf == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	*surf = info->surf;

	return AUL_R_OK;
}

API int aul_widget_info_get_widget_id(aul_widget_info_h info, char **widget_id)
{
	if (info == NULL || widget_id == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	*widget_id = strdup(info->widget_id);
	if (*widget_id == NULL) {
		_E("Out of memory");
		return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_widget_info_get_instance_id(aul_widget_info_h info,
		char **instance_id)
{
	if (info == NULL || instance_id == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	*instance_id = strdup(info->instance_id);
	if (*instance_id == NULL) {
		_E("Out of memory");
		return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_widget_info_get_app_id(aul_widget_info_h info, char **app_id)
{
	if (info == NULL || app_id == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	*app_id = strdup(info->app_id);
	if (*app_id == NULL) {
		_E("Out of memory");
		return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_widget_info_get_package_id(aul_widget_info_h info,
		char **package_id)
{
	if (info == NULL || package_id == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	*package_id = strdup(info->package_id);
	if (*package_id == NULL) {
		_E("Out of memory");
		return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_widget_info_get_app_path(aul_widget_info_h info, char **app_path)
{
	if (info == NULL || app_path == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	*app_path = strdup(info->app_path);
	if (*app_path == NULL) {
		_E("Out of memory");
		return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_widget_instance_change_status(const char *widget_id,
		const char *status)
{
	int ret;
	bundle *kb;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	bundle_add_str(kb, AUL_K_STATUS, status);
	bundle_add_str(kb, AUL_K_WIDGET_ID, widget_id);
	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			WIDGET_CHANGE_STATUS, kb, AUL_SOCK_NOREPLY);

	bundle_free(kb);
	if (ret < 0) {
		_E("send error %d, %s", ret, status);
		return aul_error_convert(ret);
	}

	return AUL_R_OK;
}
