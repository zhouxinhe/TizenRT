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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <ctype.h>
#include <glib.h>
#include <gio/gio.h>
#include <bundle_internal.h>

#include "aul_api.h"
#include "aul_cmd.h"
#include "aul_util.h"
#include "aul.h"
#include "aul_sock.h"
#include "launch.h"
#include "key.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

struct aul_request_s {
	int cmd;
	int clifd;
	bundle *b;
};

typedef struct aul_request_s *aul_request_h;

typedef void (*dispatcher)(aul_request_h req);

typedef struct aul_handler_s {
	aul_handler_fn callback;
	void *user_data;
} aul_handler;

typedef struct subapp_handler_s {
	bool is_subapp;
	subapp_fn callback;
	void *user_data;
} subapp_handler;

typedef struct data_control_provider_handler_s {
	data_control_provider_handler_fn callback;
} data_control_provider_handler;

typedef struct launch_context_s {
	GIOChannel *io;
	guint source;
	aul_handler aul;
	subapp_handler subapp;
	data_control_provider_handler dcp;
} launch_context;

static launch_context __context;

static void __invoke_aul_handler(aul_type type, bundle *b)
{
	if (__context.aul.callback)
		__context.aul.callback(type, b, __context.aul.user_data);
}

static void __dispatch_app_start(aul_request_h req)
{
	const char *str;

	__invoke_aul_handler(AUL_START, req->b);
	str = bundle_get_val(req->b, AUL_K_DATA_CONTROL_TYPE);
	if (str && !strcmp(str, "CORE")) {
		if (__context.dcp.callback)
			__context.dcp.callback(req->b, 0, NULL);
	}
}

static void __dispatch_app_resume(aul_request_h req)
{
	__invoke_aul_handler(AUL_RESUME, NULL);
}

static void __dispatch_app_term_by_pid(aul_request_h req)
{
	__invoke_aul_handler(AUL_TERMINATE, NULL);
}

static void __dispatch_app_term_bgapp_by_pid(aul_request_h req)
{
	__invoke_aul_handler(AUL_TERMINATE_BGAPP, NULL);
}

static void __dispatch_app_term_req_by_pid(aul_request_h req)
{
	if (__context.subapp.is_subapp) {
		if (__context.subapp.callback)
			__context.subapp.callback(__context.subapp.user_data);
	} else {
		__invoke_aul_handler(AUL_TERMINATE, NULL);
	}
}

static void __dispatch_app_result(aul_request_h req)
{
	const char *pid_str;
	int pid = -1;

	pid_str = bundle_get_val(req->b, AUL_K_CALLEE_PID);
	if (pid_str)
		pid = atoi(pid_str);

	app_result(req->cmd, req->b, pid);
}

static void __dispatch_app_key_event(aul_request_h req)
{
	app_key_event(req->b);
}

static void __dispatch_app_pause_by_pid(aul_request_h req)
{
	__invoke_aul_handler(AUL_PAUSE, req->b);
}

static void __dispatch_app_com_message(aul_request_h req)
{
	app_com_recv(req->b);
}

static void __dispatch_app_wake(aul_request_h req)
{
	__invoke_aul_handler(AUL_WAKE, req->b);
}

static void __dispatch_app_suspend(aul_request_h req)
{
	__invoke_aul_handler(AUL_SUSPEND, req->b);
}

static void __dispatch_widget_get_content(aul_request_h req)
{
	const char *widget_id;
	const char *instance_id;
	const char *content_info;
	int fds[2] = { 0, };
	int r;

	r = aul_sock_recv_reply_sock_fd(req->clifd, &fds, 1);
	if (r < 0) {
		_E("Failed to receive fds");
		return;
	}

	widget_id = bundle_get_val(req->b, AUL_K_WIDGET_ID);
	if (!widget_id) {
		_E("Failed to get widget ID");
		aul_sock_send_raw_with_fd(fds[0], -EINVAL, 0, 0,
				AUL_SOCK_NOREPLY);
		return;
	}

	instance_id = bundle_get_val(req->b, AUL_K_WIDGET_INSTANCE_ID);
	if (!instance_id) {
		_E("Failed to get instance ID");
		aul_sock_send_raw_with_fd(fds[0], -EINVAL, 0, 0,
				AUL_SOCK_NOREPLY);
		return;
	}

	__invoke_aul_handler(AUL_WIDGET_CONTENT, req->b);

	content_info = bundle_get_val(req->b, AUL_K_WIDGET_CONTENT_INFO);
	if (content_info) {
		r = aul_sock_send_raw_with_fd(fds[0], 0,
				(unsigned char *)content_info,
				strlen(content_info) + 1, AUL_SOCK_NOREPLY);
	} else {
		r = aul_sock_send_raw_with_fd(fds[0], -ENOENT,
				NULL, 0, AUL_SOCK_NOREPLY);
	}

	if (r < 0) {
		_E("Failed to send content info. fd(%d), result(%d)",
				fds[0], r);
	}
}

static void __dispatch_app_update_requested(aul_request_h req)
{
	__invoke_aul_handler(AUL_UPDATE_REQUESTED, req->b);
}

static void __dispatch_watchdog_ping(aul_request_h req)
{
	const char *start_time;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	start_time = bundle_get_val(req->b, AUL_K_STARTTIME);
	_W("[__WATCHDOG__] Start time: %s, response time: %ld/%ld",
			start_time ? start_time : "Unknown",
			tv.tv_sec, tv.tv_usec);
}

static dispatcher __dispatcher[] = {
	[APP_START] = __dispatch_app_start,
	[APP_START_RES] = __dispatch_app_start,
	[APP_START_ASYNC] = __dispatch_app_start,
	[APP_START_RES_ASYNC] = __dispatch_app_start,
	[APP_OPEN] = __dispatch_app_resume,
	[APP_RESUME] = __dispatch_app_resume,
	[APP_RESUME_BY_PID] = __dispatch_app_resume,
	[APP_TERM_BY_PID] = __dispatch_app_term_by_pid,
	[APP_TERM_BY_PID_ASYNC] = __dispatch_app_term_by_pid,
	[APP_TERM_BY_PID_SYNC] = __dispatch_app_term_by_pid,
	[APP_TERM_BGAPP_BY_PID] = __dispatch_app_term_bgapp_by_pid,
	[APP_TERM_REQ_BY_PID] = __dispatch_app_term_req_by_pid,
	[APP_RESULT] = __dispatch_app_result,
	[APP_CANCEL] = __dispatch_app_result,
	[APP_KEY_EVENT] = __dispatch_app_key_event,
	[APP_PAUSE_BY_PID] = __dispatch_app_pause_by_pid,
	[APP_COM_MESSAGE] = __dispatch_app_com_message,
	[APP_WAKE] = __dispatch_app_wake,
	[APP_SUSPEND] = __dispatch_app_suspend,
	[WIDGET_GET_CONTENT] = __dispatch_widget_get_content,
	[APP_UPDATE_REQUESTED] = __dispatch_app_update_requested,
	[WATCHDOG_PING] = __dispatch_watchdog_ping,
	[APP_SEND_LAUNCH_REQUEST] = __dispatch_app_start,
};

static gboolean __aul_launch_handler(GIOChannel *io, GIOCondition condition,
		gpointer data)
{
	int fd = g_io_channel_unix_get_fd(io);
	struct aul_request_s req = { 0, };
	app_pkt_t *pkt;
	bundle *b = NULL;
	int clifd;
	struct ucred cr;
	int r;

	pkt = aul_sock_recv_pkt(fd, &clifd, &cr);
	if (!pkt) {
		_E("Failed to receive the packet");
		return G_SOURCE_CONTINUE;
	}

	if (pkt->cmd != WIDGET_GET_CONTENT) {
		if (pkt->opt & AUL_SOCK_NOREPLY) {
			close(clifd);
			clifd = -1;
		} else {
			r = aul_sock_send_result(clifd, 0);
			if (r < 0) {
				_E("Failed to send result. cmd(%s:%d)",
					aul_cmd_convert_to_string(pkt->cmd),
					pkt->cmd);
				free(pkt);
				return G_SOURCE_CONTINUE;;
			}
			clifd = -1;
		}
	}

	if (pkt->opt & AUL_SOCK_BUNDLE) {
		b = bundle_decode(pkt->data, pkt->len);
		if (!b) {
			_E("Failed to decode the packet");
			if (clifd > 0)
				close(clifd);
			free(pkt);
			return G_SOURCE_CONTINUE;
		}
	}

	req.cmd = pkt->cmd;
	req.clifd = clifd;
	req.b = b;

	free(pkt);

	if (req.cmd >= APP_START && req.cmd < ARRAY_SIZE(__dispatcher) &&
			__dispatcher[req.cmd]) {
		_W("Command(%s:%d)",
				aul_cmd_convert_to_string(req.cmd), req.cmd);
		__dispatcher[req.cmd](&req);
	} else {
		_E("Command(%s:%d) is not available",
				aul_cmd_convert_to_string(req.cmd), req.cmd);
	}

	if (req.b)
		bundle_free(req.b);

	return G_SOURCE_CONTINUE;
}

static void __finalize_context(void)
{
	if (__context.source) {
		g_source_remove(__context.source);
		__context.source = 0;
	}

	if (__context.io) {
		g_io_channel_unref(__context.io);
		__context.io = NULL;
	}
}

static int __initialize_context(void)
{
	GIOCondition cond = G_IO_IN | G_IO_PRI | G_IO_HUP | G_IO_ERR;
	int fd;

	fd = aul_initialize();
	if (fd < 0) {
		_E("Failed to initialize aul");
		return fd;
	}

	__context.io = g_io_channel_unix_new(fd);
	if (!__context.io) {
		_E("Failed to create gio channel");
		__finalize_context();
		return AUL_R_ERROR;
	}

	__context.source = g_io_add_watch(__context.io,
			cond, __aul_launch_handler, NULL);
	if (!__context.source) {
		_E("Failed to add gio watch");
		__finalize_context();
		return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_launch_init(aul_handler_fn callback, void *user_data)
{
	if (callback) {
		__context.aul.callback = callback;
		__context.aul.user_data = user_data;
	}

	return __initialize_context();
}

API int aul_launch_fini(void)
{
	__finalize_context();
	return AUL_R_OK;
}

static gboolean __app_start_cb(gpointer data)
{
	bundle *b = (bundle *)data;
	struct aul_request_s req = {
		.cmd = APP_START,
		.clifd = 0,
		.b = b
	};

	__dispatch_app_start(&req);

	if (req.b)
		bundle_free(req.b);

	return G_SOURCE_REMOVE;
}

API int aul_launch_argv_handler(int argc, char **argv)
{
	bundle *b;

	if (!aul_is_initialized()) {
		_E("AUL is not initialized");
		return AUL_R_ENOINIT;
	}

	b = bundle_import_from_argv(argc, argv);
	if (!b)
		_E("Bundle is nullptr");

	if (!g_idle_add_full(G_PRIORITY_HIGH, __app_start_cb, b, NULL)) {
		_E("Failed to add idler");
		return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_launch_local(bundle *b)
{
	if (!aul_is_initialized()) {
		_E("AUL is not initialized");
		return AUL_R_ENOINIT;
	}

	if (!b)
		_E("Bundle is nullptr");

	if (!g_idle_add(__app_start_cb, b)) {
		_E("Failed to add idler");
		return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

int aul_resume_local(void)
{
	if (!aul_is_initialized()) {
		_E("AUL is not initialized");
		return AUL_R_ENOINIT;
	}

	__dispatch_app_resume(NULL);

	return AUL_R_OK;
}

API int aul_set_subapp(subapp_fn callback, void *user_data)
{
	__context.subapp.is_subapp = true;
	__context.subapp.callback = callback;
	__context.subapp.user_data = user_data;

	return AUL_R_OK;
}

API int aul_is_subapp(void)
{
	return (int)__context.subapp.is_subapp;
}

API int aul_set_data_control_provider_cb(data_control_provider_handler_fn cb)
{
	__context.dcp.callback = cb;

	return AUL_R_OK;
}

API int aul_unset_data_control_provider_cb(void)
{
	__context.dcp.callback = NULL;

	return AUL_R_OK;
}
