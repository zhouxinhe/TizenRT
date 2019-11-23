/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <bundle_internal.h>

#include "aul_api.h"
#include "aul_util.h"
#include "aul_sock.h"
#include "aul_rpc_port.h"
#include "aul.h"

static bundle *__create_bundle(const char *appid, const char *port_name)
{
	bundle *b;
	int r;

	b = bundle_create();
	if (!b) {
		_E("Out of memory");
		return NULL;
	}

	r = bundle_add(b, AUL_K_APPID, appid);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add appid(%s)", appid);
		bundle_free(b);
		return NULL;
	}

	r = bundle_add(b, AUL_K_RPC_PORT, port_name);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add port_name(%s)", port_name);
		bundle_free(b);
		return NULL;
	}

	return b;
}

API int aul_rpc_port_prepare_stub(const char *appid, const char *port_name)
{
	bundle *b;
	int r;

	if (!appid || !port_name) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	b = __create_bundle(appid, port_name);
	if (!b)
		return AUL_R_ERROR;

	r = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			RPC_PORT_PREPARE_STUB, b, AUL_SOCK_QUEUE);
	if (r < 0) {
		_E("Failed to send request(%d:%s)",
				RPC_PORT_PREPARE_STUB, appid);
		bundle_free(b);
		return r;
	}
	bundle_free(b);

	return AUL_R_OK;
}

API int aul_rpc_port_create_socket_pair(const char *appid,
		const char *port_name, int (*fds)[2])
{
	bundle *b;
	int fd;
	int r;

	if (!appid || !port_name || !fds) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	b = __create_bundle(appid, port_name);
	if (!b)
		return AUL_R_ERROR;

	fd = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			RPC_PORT_CREATE_SOCKET_PAIR, b, AUL_SOCK_ASYNC);
	if (fd <= 0 || fd > sysconf(_SC_OPEN_MAX)) {
		_E("Failed to send socket pair creation request. err = %d", fd);
		bundle_free(b);
		return fd;
	}
	bundle_free(b);

	r = aul_sock_recv_reply_sock_fd(fd, fds, 2);
	if (r != 0) {
		_E("Failed to receive socket fds. err = %d", r);
		return r;
	}

	return AUL_R_OK;
}

API int aul_rpc_port_notify_rpc_finished(void)
{
	char buf[12];
	bundle *b;
	int r;

	b = bundle_create();
	if (!b) {
		_E("Out of memory");
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%d", getpid());
	r = bundle_add(b, AUL_K_PID, buf);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add pid(%d). err = %d", getpid(), r);
		bundle_free(b);
		return AUL_R_ERROR;
	}

	r = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			RPC_PORT_NOTIFY_RPC_FINISHED, b, AUL_SOCK_NOREPLY);
	if (r != 0) {
		_E("Failed to notify rpc finished(%d). err = %d", getpid(), r);
		bundle_free(b);
		return r;
	}
	bundle_free(b);

	return AUL_R_OK;
}

