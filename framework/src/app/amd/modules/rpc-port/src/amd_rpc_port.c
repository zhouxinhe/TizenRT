/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <ctype.h>
#include <sys/socket.h>
#include <glib.h>
#include <gio/gio.h>
#include <aul.h>
#include <aul_cmd.h>
#include <aul_rpc_port.h>
#include <aul_svc.h>
#include <aul_sock.h>
#include <bundle_internal.h>
#include <cert-svc/ccert.h>
#include <cert-svc/cinstance.h>
#include <amd.h>

#include "amd_rpc_port_private.h"

#define ARRAY_SIZE(x) ((sizeof(x)) / sizeof(x[0]))
#define MAX_NR_OF_DESCRIPTORS 2
#define PRIVILEGE_DATASHARING "http://tizen.org/privilege/datasharing"
#define KEY_PRIVILEGE_CHECK_BYPASS \
	"http://tizen.org/rpc-port/privilege-check-bypass"

struct metadata_info_s {
	const char *port_name;
	bool exist;
};

static GHashTable *__pid_table;

static void __rpc_unref(int pid)
{
	gpointer value;
	int count;
	amd_app_status_h app_status;
	int status;

	value = g_hash_table_lookup(__pid_table, GINT_TO_POINTER(pid));
	if (!value) {
		_E("Critical error");
		return;
	}

	count = GPOINTER_TO_INT(value);
	count--;
	if (count == 0) {
		g_hash_table_remove(__pid_table, GINT_TO_POINTER(pid));
		amd_suspend_update_status(pid, AMD_SUSPEND_STATUS_INCLUDE);
		app_status = amd_app_status_find_by_pid(pid);
		if (app_status) {
			status = amd_app_status_get_status(app_status);
			if (status != STATUS_DYING)
				amd_suspend_add_timer(pid);
		}
	} else {
		g_hash_table_replace(__pid_table, GINT_TO_POINTER(pid),
				GINT_TO_POINTER(count));
	}
}

static void __rpc_ref(int pid)
{
	gpointer value;
	int count;

	value = g_hash_table_lookup(__pid_table, GINT_TO_POINTER(pid));
	if (value) {
		count = GPOINTER_TO_INT(value);
		count++;
		g_hash_table_replace(__pid_table, GINT_TO_POINTER(pid),
				GINT_TO_POINTER(count));
	} else {
		count = 1;
		g_hash_table_insert(__pid_table, GINT_TO_POINTER(pid),
				GINT_TO_POINTER(count));
		amd_suspend_remove_timer(pid);
		amd_suspend_update_status(pid, AMD_SUSPEND_STATUS_EXCLUDE);
	}
}

static void __set_real_appid(uid_t uid, bundle *kb)
{
	const char *alias_appid;
	const char *appid;
	const char *alias_info;
	amd_app_property_h app_property;

	alias_appid = bundle_get_val(kb, AUL_K_APPID);
	if (alias_appid == NULL)
		return;

	alias_info = bundle_get_val(kb, AUL_SVC_K_ALIAS_INFO);
	if (alias_info && strcmp(alias_info, "disable") == 0)
		return;

	app_property = amd_app_property_find(uid);
	if (app_property == NULL)
		return;

	appid = amd_app_property_get_real_appid(app_property, alias_appid);
	if (appid == NULL)
		return;

	_D("alias_appid(%s), appid(%s)", alias_appid, appid);
	bundle_del(kb, AUL_K_ORG_APPID);
	bundle_add(kb, AUL_K_ORG_APPID, alias_appid);
	bundle_del(kb, AUL_K_APPID);
	bundle_add(kb, AUL_K_APPID, appid);
}

static int __dispatch_rpc_port_prepare_stub(amd_request_h req)
{
	bundle *b = amd_request_get_bundle(req);
	pid_t caller_pid = amd_request_get_pid(req);
	uid_t target_uid = amd_request_get_target_uid(req);
	amd_appinfo_h ai;
	const char *appid;
	const char *port_name;
	int pid;
	bool dummy_pending = false;
	bool dummy_bg_launch = false;

	if (!b) {
		_E("Invalid parameter");
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	__set_real_appid(target_uid, b);

	appid = bundle_get_val(b, AUL_K_APPID);
	if (!appid) {
		_E("Failed to get appid");
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	port_name = bundle_get_val(b, AUL_K_RPC_PORT);
	if (!port_name) {
		_E("Failed to get port name");
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	ai = amd_appinfo_find(target_uid, appid);
	if (!ai) {
		_E("Failed to find %s:%u", appid, target_uid);
		amd_request_send_result(req, -ENOENT);
		return -1;
	}

	amd_noti_send("launch.app_start.start", 0, 0, req, b);
	amd_request_set_request_type(req, "rpc-port");
	amd_request_set_cmd(req, APP_START_ASYNC);
	pid = amd_launch_start_app(appid, req,
			&dummy_pending, &dummy_bg_launch,
			false);
	if (pid < 0) {
		_E("Failed to send launch request(%s:%s)",
				appid, port_name);
		amd_noti_send("launch.fail", pid, 0, NULL, NULL);
		return -1;
	}
	amd_noti_send("launch.app_start.end", pid, dummy_bg_launch, req, b);

	__rpc_ref(pid);

	_I("[__RPC_PORT__] appid(%s), pid(%d), port_name(%s), caller_pid(%d)",
			appid, pid, port_name, caller_pid);

	return 0;
}

static int __pass_fds(int fd, const int (*fds)[2])
{
	struct msghdr msg = { 0, };
	struct cmsghdr *cmsg;
	union {
		/*
		 * ancillary data buffer, wrapped in a union in order to ensure
		 * it is suitably aligned
		 */
		char buf[CMSG_SPACE(sizeof(int) * MAX_NR_OF_DESCRIPTORS)];
		struct cmsghdr align;
	} u;
	int *fdptr;
	char iobuf[1];
	struct iovec io = {
		.iov_base = iobuf,
		.iov_len = sizeof(iobuf)
	};
	int r;

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		_E("Failed to get the first cmsghdr");
		return -EINVAL;
	}

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int) * MAX_NR_OF_DESCRIPTORS);

	/* Initialize the payload: */
	fdptr = (int *)CMSG_DATA(cmsg);
	memcpy(fdptr, *fds, sizeof(int) * MAX_NR_OF_DESCRIPTORS);

	r = sendmsg(fd, &msg, 0);
	if (r < 0) {
		_E("Failed to send message. errno(%d)", errno);
		return r;
	}

	_D("[__RPC_PORT__] sendmsg result(%d)", r);

	return r;
}

static int __dispatch_rpc_port_create_socket_pair(amd_request_h req)
{
	int fds[2] = { 0, };
	int r;

	r = socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds);
	if (r != 0) {
		_E("Failed to create socket pair. err = %d", r);
		amd_request_send_result(req, -1);
		return -1;
	}

	if (fds[0] == -1) {
		_E("Failed to open socket");
		amd_request_send_result(req, -1);
		return -1;
	}

	_I("[__RPC_PORT__] A Pair of sockets: %d:%d", fds[0], fds[1]);

	r = __pass_fds(amd_request_get_fd(req), &fds);
	if (r < 0) {
		_E("Failed to pass file descriptors");
		amd_request_send_result(req, r);
	}

	close(fds[0]);
	close(fds[1]);

	return 0;
}

static int __dispatch_rpc_port_notify_rpc_finished(amd_request_h req)
{
	pid_t pid = amd_request_get_pid(req);

	if (pid <= 0) {
		_E("Invalid parameter");
		return -1;
	}

	__rpc_unref(pid);
	_I("[__RPC_PORT__] pid(%d)", pid);

	return 0;
}

static bool __has_platform_cert(const char *appid, uid_t uid)
{
	amd_appinfo_h ai;
	const char *pkgid;
	const char *visibility_str;
	int visibility;
	char buf[12];

	ai = amd_appinfo_find(uid, appid);
	if (!ai)
		return false;

	visibility_str = amd_appinfo_get_value(ai, AMD_AIT_VISIBILITY);
	if (!visibility_str) {
		pkgid = amd_appinfo_get_value(ai, AMD_AIT_PKGID);
		visibility = amd_appinfo_get_cert_visibility(pkgid, uid);
		snprintf(buf, sizeof(buf), "%d", visibility);
		amd_appinfo_set_value(ai, AMD_AIT_VISIBILITY, buf);
		visibility_str = buf;
	}

	visibility = atoi(visibility_str);
	if (visibility & CERTSVC_VISIBILITY_PLATFORM)
		return true;

	return false;
}

static int __foreach_metadata_cb(const char *value, void *user_data)
{
	struct metadata_info_s *info = (struct metadata_info_s *)user_data;
	char *str;
	char *token;
	char *saveptr = NULL;

	str = strdup(value);
	if (!str) {
		_E("Out of memory");
		return -1;
	}

	token = strtok_r(str, "|", &saveptr);
	while (token) {
		if (!strcmp(token, info->port_name)) {
			info->exist = true;
			free(str);
			return -1; /* To break metadata iteration */
		}
		token = strtok_r(NULL, "|", &saveptr);
	}

	free(str);

	return 0;
}

static int __verify_privilege_check_bypass(amd_request_h req)
{
	int r;
	bundle *b;
	const char *appid;
	struct metadata_info_s info = { 0, };
	amd_app_property_h app_property;
	uid_t uid = amd_request_get_target_uid(req);

	b = amd_request_get_bundle(req);
	if (!b) {
		_E("Invalid request");
		return AMD_CYNARA_RET_ERROR;
	}

	appid = bundle_get_val(b, AUL_K_APPID);
	if (!appid) {
		_E("Failed to get appid");
		return AMD_CYNARA_RET_ERROR;
	}

	info.port_name = bundle_get_val(b, AUL_K_RPC_PORT);
	if (!info.port_name) {
		_E("Failed to get port name");
		return AMD_CYNARA_RET_ERROR;
	}

	app_property = amd_app_property_find(uid);
	if (app_property) {
		r = amd_app_property_metadata_foreach(app_property,
				appid, KEY_PRIVILEGE_CHECK_BYPASS,
				__foreach_metadata_cb, &info);
		if (r != 0) {
			_E("Failed to retrieve metadata");
			return AMD_CYNARA_RET_ERROR;
		}

		if (info.exist && __has_platform_cert(appid, uid)) {
			SECURE_LOGD("Bypass privilege check");
			return AMD_CYNARA_RET_ALLOWED;
		}
	}

	return AMD_CYNARA_RET_UNKNOWN;
}

static int __prepare_stub_cynara_checker(amd_cynara_caller_info_h info,
		amd_request_h req, void *data)
{
	int r;

	r = __verify_privilege_check_bypass(req);
	if (r != AMD_CYNARA_RET_UNKNOWN)
		return r;

	r = amd_cynara_simple_checker(info, req, PRIVILEGE_APPMANAGER_LAUNCH);
	if (r <= AMD_CYNARA_RET_DENIED)
		return r;

	return amd_cynara_simple_checker(info, req, PRIVILEGE_DATASHARING);
}

static int __create_socket_pair_cynara_checker(amd_cynara_caller_info_h info,
		amd_request_h req, void *data)
{
	int r;

	r = __verify_privilege_check_bypass(req);
	if (r != AMD_CYNARA_RET_UNKNOWN)
		return r;

	return amd_cynara_simple_checker(info, req, PRIVILEGE_DATASHARING);
}

static int __on_app_status_cleanup(const char *msg, int arg1, int arg2,
		void *arg3, bundle *b)
{
	int pid = arg1;

	if (g_hash_table_contains(__pid_table, GINT_TO_POINTER(pid)))
		g_hash_table_remove(__pid_table, GINT_TO_POINTER(pid));

	return 0;
}

static amd_request_cmd_dispatch __dispatch_table[] = {
	{
		.cmd = RPC_PORT_PREPARE_STUB,
		.callback = __dispatch_rpc_port_prepare_stub
	},
	{
		.cmd = RPC_PORT_CREATE_SOCKET_PAIR,
		.callback = __dispatch_rpc_port_create_socket_pair
	},
	{
		.cmd = RPC_PORT_NOTIFY_RPC_FINISHED,
		.callback = __dispatch_rpc_port_notify_rpc_finished
	},
};

static amd_cynara_checker __cynara_checkers[] = {
	{
		.cmd = RPC_PORT_PREPARE_STUB,
		.checker = __prepare_stub_cynara_checker,
		.data = NULL,
		.priority = 10
	},
	{
		.cmd = RPC_PORT_CREATE_SOCKET_PAIR,
		.checker = __create_socket_pair_cynara_checker,
		.data = NULL,
		.priority = 10
	},
};

EXPORT int AMD_MOD_INIT(void)
{
	int r;

	_D("rpc port init");

	r = amd_app_property_metadata_add_filter(KEY_PRIVILEGE_CHECK_BYPASS,
			NULL);
	if (r < 0) {
		_E("Failed to add metadata filter");
		return -1;
	}

	r = amd_request_register_cmds(__dispatch_table,
			ARRAY_SIZE(__dispatch_table));
	if (r < 0) {
		_E("Failed to register cmds");
		return -1;
	}

	r = amd_cynara_register_checkers(__cynara_checkers,
			ARRAY_SIZE(__cynara_checkers));
	if (r < 0) {
		_E("Failed to register cynara checkers");
		return -1;
	}

	__pid_table = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (!__pid_table) {
		_E("Failed to create pid table");
		return -1;
	}

	amd_noti_listen("app_status.cleanup", __on_app_status_cleanup);

	return 0;
}

EXPORT void AMD_MOD_FINI(void)
{
	_D("rpc port finish");

	if (__pid_table)
		g_hash_table_destroy(__pid_table);

	amd_app_property_metadata_remove_filter(KEY_PRIVILEGE_CHECK_BYPASS,
			NULL);
}
