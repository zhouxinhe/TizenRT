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
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <fcntl.h>
#include <aul.h>
#include <aul_sock.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <pkgmgr-info.h>
#include <vconf.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_request.h"
#include "amd_appinfo.h"
#include "amd_app_status.h"
#include "amd_socket.h"
#include "amd_cynara.h"
#include "amd_noti.h"

#define OSP_K_DATACONTROL_PROVIDER "__OSP_DATACONTROL_PROVIDER__"
#define MAX_NR_OF_DESCRIPTORS 2
#define AMD_LOG_BUFFER_SIZE 131072
#define AMD_LOG_BUFFER_STRING_SIZE 128
#define AMD_LOG_FILE "/run/aul/log/amd.log"

static int log_index;
static int log_fd;
static GHashTable *__dc_socket_pair_hash;
static int datacontrol_result;
static int __memory_status;
static bool __vconf_initialized;
static guint __vconf_init_timer;

int _util_save_log(const char *tag, const char *message)
{
	int ret;
	int offset;
	time_t now;
	char time_buf[32] = {0,};
	char buffer[AMD_LOG_BUFFER_STRING_SIZE];

	if (log_fd < 0) {
		_E("Invalid file descriptor");
		return -1;
	}

	time(&now);
	ctime_r(&now, time_buf);

	offset = lseek(log_fd, 0, SEEK_CUR);
	if (offset >= AMD_LOG_BUFFER_SIZE)
		lseek(log_fd, 0, SEEK_SET);

	snprintf(buffer, sizeof(buffer), "[%-6d] %-15s %-50s %s",
			log_index, tag, message, time_buf);

	ret = write(log_fd, buffer, strlen(buffer));
	if (ret < 0) {
		_E("Cannot write the amd log: %d", ret);
		return -1;
	}

	if (++log_index < 0)
		log_index = 0;

	return 0;
}

static int __init_log(void)
{
	int offset;

	log_fd = open(AMD_LOG_FILE, O_CREAT | O_WRONLY, 0600);
	if (log_fd < 0) {
		_E("Failed to open %s - %d", AMD_LOG_FILE, errno);
		return -1;
	}

	offset = lseek(log_fd, 0, SEEK_END);
	if (offset >= AMD_LOG_BUFFER_SIZE)
		lseek(log_fd, 0, SEEK_SET);

	return 0;
}

static int __send_message(int sock, const struct iovec *vec, int vec_size,
		const int *desc, int nr_desc)
{
	struct msghdr msg = {0,};
	int sndret;
	int desclen = 0;
	struct cmsghdr *cmsg = NULL;
	char buff[CMSG_SPACE(sizeof(int) * MAX_NR_OF_DESCRIPTORS)] = {0,};

	if (vec == NULL || vec_size < 1)
		return -EINVAL;
	if (nr_desc < 0 || nr_desc > MAX_NR_OF_DESCRIPTORS)
		return -EINVAL;
	if (desc == NULL)
		nr_desc = 0;

	msg.msg_iov = (struct iovec *)vec;
	msg.msg_iovlen = vec_size;

	/* sending ancillary data */
	if (nr_desc > 0) {
		msg.msg_control = buff;
		msg.msg_controllen = sizeof(buff);
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL)
			return -EINVAL;

		/* packing files descriptors */
		if (nr_desc > 0) {
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			desclen = cmsg->cmsg_len =
				CMSG_LEN(sizeof(int) * nr_desc);
			memcpy((int *)CMSG_DATA(cmsg), desc,
					sizeof(int) * nr_desc);
			cmsg = CMSG_NXTHDR(&msg, cmsg);
			_D("packing file descriptors done");
		}

		/* finished packing updating the corect length */
		msg.msg_controllen = desclen;
	} else {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}

	sndret = sendmsg(sock, &msg, 0);
	_D("sendmsg ret : %d", sndret);
	if (sndret < 0)
		return -errno;

	return sndret;
}

static int __dispatch_get_mp_socket_pair(request_h req)
{
	int handles[2] = {0, 0};
	struct iovec vec[3];
	int msglen = 0;
	char buffer[1024];
	int ret = 0;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, handles) != 0) {
		_E("error create socket pair");
		_request_send_result(req, -1);
		return -1;
	}

	if (handles[0] == -1) {
		_E("error socket open");
		_request_send_result(req, -1);
		return -1;
	}

	_D("amd send mp fd : [%d, %d]", handles[0], handles[1]);
	vec[0].iov_base = buffer;
	vec[0].iov_len = strlen(buffer) + 1;

	msglen = __send_message(_request_get_fd(req), vec, 1, handles, 2);
	if (msglen < 0) {
		_E("Error[%d]: while sending message\n", -msglen);
		_request_send_result(req, -1);
		ret = -1;
	}

	close(handles[0]);
	close(handles[1]);

	return ret;
}

static int *__check_dc_socket_pair_handle(char *socket_pair_key,
		const char *datacontrol_type)
{
	int *handles;

	handles = g_hash_table_lookup(__dc_socket_pair_hash, socket_pair_key);
	if (handles == NULL)
		return NULL;

	if (strcmp(datacontrol_type, "consumer") == 0) {
		if (handles[0] == -1) {
			g_hash_table_remove(__dc_socket_pair_hash,
					socket_pair_key);
			return NULL;
		}
	} else {
		if (handles[1] == -1) {
			g_hash_table_remove(__dc_socket_pair_hash,
					socket_pair_key);
			return NULL;
		}
	}

	return handles;
}

static int __dispatch_get_dc_socket_pair(request_h req)
{
	const char *caller;
	const char *callee;
	const char *datacontrol_type;
	char *socket_pair_key = NULL;
	int socket_pair_key_len;
	int *handles = NULL;
	struct iovec vec[3];
	int msglen = 0;
	char buffer[1024];
	bundle *kb = _request_get_bundle(req);

	caller = bundle_get_val(kb, AUL_K_CALLER_APPID);
	if (caller == NULL)
		goto err_out;
	callee = bundle_get_val(kb, AUL_K_CALLEE_APPID);
	if (callee == NULL)
		goto err_out;
	datacontrol_type = bundle_get_val(kb, "DATA_CONTROL_TYPE");
	if (datacontrol_type == NULL)
		goto err_out;

	socket_pair_key_len = strlen(caller) + strlen(callee) + 2;

	socket_pair_key = (char *)calloc(socket_pair_key_len, sizeof(char));
	if (socket_pair_key == NULL) {
		_E("calloc fail");
		goto err_out;
	}

	snprintf(socket_pair_key, socket_pair_key_len, "%s_%s", caller, callee);
	_D("socket pair key : %s", socket_pair_key);

	handles = __check_dc_socket_pair_handle(socket_pair_key,
			datacontrol_type);
	if (handles == NULL) {
		handles = (int *)calloc(2, sizeof(int));
		if (handles == NULL) {
			_E("calloc fail");
			goto err_out;
		}

		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, handles) != 0) {
			_E("error create socket pair");
			free(handles);
			handles = NULL;
			goto err_out;
		}

		if (handles[0] == -1 || handles[1] == -1) {
			_E("error socket open");
			free(handles);
			handles = NULL;
			goto err_out;
		}

		g_hash_table_insert(__dc_socket_pair_hash,
				strdup(socket_pair_key), handles);
		_D("New socket pair insert done.");
	}

	SECURE_LOGD("amd send fd : [%d, %d]", handles[0], handles[1]);
	vec[0].iov_base = buffer;
	vec[0].iov_len = 1;

	_send_result_to_client_v2(_request_get_fd(req), 0);

	if (datacontrol_type != NULL) {
		_D("datacontrol_type : %s", datacontrol_type);
		if (strcmp(datacontrol_type, "consumer") == 0) {
			msglen = __send_message(_request_get_fd(req), vec, 1,
					&handles[0], 1);
			if (msglen < 0) {
				_E("Error[%d]: while sending message", -msglen);
				goto err_out;
			}
			close(handles[0]);
			handles[0] = -1;
			if (handles[1] == -1) {
				_D("remove from hash : %s", socket_pair_key);
				g_hash_table_remove(__dc_socket_pair_hash,
						socket_pair_key);
			}

		} else {
			msglen = __send_message(_request_get_fd(req), vec, 1,
					&handles[1], 1);
			if (msglen < 0) {
				_E("Error[%d]: while sending message", -msglen);
				goto err_out;
			}
			close(handles[1]);
			handles[1] = -1;
			if (handles[0] == -1) {
				_D("remove from hash : %s", socket_pair_key);
				g_hash_table_remove(__dc_socket_pair_hash,
						socket_pair_key);
			}
		}
	}
	SECURE_LOGD("send_message msglen : [%d]\n", msglen);
	if (socket_pair_key)
		free(socket_pair_key);

	return 0;

err_out:
	_request_send_result(req, -1);
	if (socket_pair_key) {
		g_hash_table_remove(__dc_socket_pair_hash, socket_pair_key);
		free(socket_pair_key);
	}

	return -1;
}

static int __dispatch_app_set_process_group(request_h req)
{
	int owner_pid;
	int child_pid;
	bundle *kb = NULL;
	const char *child_appid;
	const char *child_pkgid = NULL;
	const struct appinfo *ai;
	const char *str_pid;
	app_status_h app_status;
	int ret;

	kb = _request_get_bundle(req);
	if (kb == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	str_pid = bundle_get_val(kb, AUL_K_OWNER_PID);
	if (str_pid == NULL) {
		_E("No owner pid");
		_request_send_result(req, -1);
		return -1;
	}

	owner_pid = atoi(str_pid);
	str_pid = bundle_get_val(kb, AUL_K_CHILD_PID);
	if (str_pid == NULL) {
		_E("No child pid");
		_request_send_result(req, -1);
		return -1;
	}

	child_pid = atoi(str_pid);
	app_status = _app_status_find(child_pid);
	if (app_status) {
		child_appid = _app_status_get_appid(app_status);
		ai = _appinfo_find(_request_get_target_uid(req), child_appid);
		child_pkgid = _appinfo_get_value(ai, AIT_PKGID);
	}

	ret = aul_send_app_group_signal(owner_pid, child_pid, child_pkgid);

	_request_send_result(req, ret);
	return 0;
}

struct checker_info {
	caller_info_h caller;
	request_h req;
};

int __datacontrol_privilege_func(const char *privilege_name, void *user_data)
{
	int ret;
	struct checker_info *info = (struct checker_info*)user_data;

	ret = _cynara_simple_checker(info->caller, info->req,
			(void *)privilege_name);
	if (ret >= 0 && datacontrol_result == AMD_CYNARA_UNKNOWN)
		return ret;

	datacontrol_result = ret;
	return ret;
}

static int __datacontrol_provider_checker(caller_info_h info, request_h req,
		void *data)
{
	bundle *b;
	char *provider_id;
	char *type;
	char *data_type;
	int ret;
	struct checker_info checker = {
		.caller = info,
		.req = req
	};

	b = _request_get_bundle(req);
	if (b == NULL)
		return -1;

	ret = bundle_get_str(b, "DATA_CONTROL_TYPE", &type);
	if (ret < 0)
		return -1;

	if (strcmp(type, "provider") == 0)
		return 0;

	ret = bundle_get_str(b, OSP_K_DATACONTROL_PROVIDER, &provider_id);
	if (ret < 0)
		return -1;

	ret = bundle_get_str(b, "DATA_CONTROL_DATA_TYPE", &data_type);
	if (ret < 0)
		return -1;

	datacontrol_result = 0;

	ret = pkgmgrinfo_appinfo_usr_foreach_datacontrol_privileges(provider_id,
			data_type, __datacontrol_privilege_func,
			&checker, _request_get_target_uid(req));
	if (ret < 0) {
		_E("pkgmgrinfo_appinfo_usr_foreach_datacontrol_privileges failed");
		return -1;
	}

	return datacontrol_result;
}

static request_cmd_dispatch __dispatch_table[] = {
	{
		.cmd = APP_GET_DC_SOCKET_PAIR,
		.callback = __dispatch_get_dc_socket_pair
	},
	{
		.cmd = APP_GET_MP_SOCKET_PAIR,
		.callback = __dispatch_get_mp_socket_pair
	},
	{
		.cmd = APP_SET_PROCESS_GROUP,
		.callback = __dispatch_app_set_process_group
	},
};

static cynara_checker __cynara_checkers[] = {
	{
		.cmd = APP_GET_DC_SOCKET_PAIR,
		.checker = __datacontrol_provider_checker,
		.data = NULL,
	},
};

static void __free_socket_pair(gpointer data)
{
	int *handles = (int *)data;

	if (handles == NULL)
		return;

	if (handles[0] > 0)
		close(handles[0]);
	if (handles[1] > 0)
		close(handles[1]);
	free(handles);
}

static void __memory_status_changed_cb(keynode_t *node, void *data)
{
	__memory_status = vconf_keynode_get_int(node);
	switch (__memory_status) {
	case VCONFKEY_SYSMAN_LOW_MEMORY_NORMAL:
		_W("Normal");
		_noti_send("util.low_memory.normal", 0, 0, NULL, NULL);
		break;
	case VCONFKEY_SYSMAN_LOW_MEMORY_SOFT_WARNING:
		_W("Soft warning");
		break;
	case VCONFKEY_SYSMAN_LOW_MEMORY_HARD_WARNING:
		_W("Hard warning");
		break;
	default:
		break;
	}
}

bool _util_check_oom(void)
{
	if (__memory_status >= VCONFKEY_SYSMAN_LOW_MEMORY_SOFT_WARNING) {
		_W("low memory");
		return true;
	}

	return false;
}

static int __init_vconf(void)
{
	int r;

	vconf_get_int(VCONFKEY_SYSMAN_LOW_MEMORY, &__memory_status);
	r = vconf_notify_key_changed(VCONFKEY_SYSMAN_LOW_MEMORY,
			__memory_status_changed_cb, NULL);
	if (r < 0) {
		_E("Failed to initialize vconf");
		return -1;
	}

	__vconf_initialized = true;

	return 0;
}

static void __finish_vconf(void)
{
	if (!__vconf_initialized)
		return;

	vconf_ignore_key_changed(VCONFKEY_SYSMAN_LOW_MEMORY,
			__memory_status_changed_cb);
	__vconf_initialized = false;
}

static gboolean __retrying_handler(gpointer data)
{
	static int retry_count;

	retry_count++;
	if (__init_vconf() < 0 && retry_count <= 10) {
		_W("Retry count(%d)", retry_count);
		return G_SOURCE_CONTINUE;
	}

	__vconf_init_timer = 0;
	return G_SOURCE_REMOVE;
}

int _util_init(void)
{
	int r;

	if (__init_log() < 0)
		return -1;

	__vconf_init_timer = g_timeout_add(500, __retrying_handler, NULL);

	__dc_socket_pair_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
			free, __free_socket_pair);
	if (__dc_socket_pair_hash == NULL) {
		_E("Failed to create socket pair table");
		return -1;
	}

	r = _request_register_cmds(__dispatch_table,
			ARRAY_SIZE(__dispatch_table));
	if (r < 0) {
		_E("Failed to register cmds");
		return -1;
	}

	r = _cynara_register_checkers(__cynara_checkers,
			ARRAY_SIZE(__cynara_checkers));
	if (r < 0) {
		_E("Failed to register checkers");
		return -1;
	}

	return 0;
}

void _util_fini(void)
{
	if (log_fd > 0)
		close(log_fd);

	if (__vconf_init_timer)
		g_source_remove(__vconf_init_timer);

	__finish_vconf();

	if (__dc_socket_pair_hash) {
		g_hash_table_destroy(__dc_socket_pair_hash);
		__dc_socket_pair_hash = NULL;
	}
}
