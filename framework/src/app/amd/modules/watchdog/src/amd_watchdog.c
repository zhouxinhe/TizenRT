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
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <glib.h>
#include <gio/gio.h>
#include <aul.h>
#include <aul_cmd.h>
#include <aul_watchdog.h>
#include <aul_sock.h>
#include <bundle_internal.h>
#include <amd.h>

#include "amd_watchdog_private.h"
#include "amd_watchdog_config.h"
#include "amd_watchdog_logger.h"

#define ARRAY_SIZE(x) ((sizeof(x)) / sizeof(x[0]))

typedef struct watchdog_s {
	GDBusConnection *conn;
	guint listener;
	guint retry_handler;
	unsigned int interval;
	int max_retry_count;
	GList *proc_contexts;
} watchdog;

typedef struct proc_context_s {
	pid_t pid;
	uid_t uid;
	bool freeze;
	bool watchdog_enable;
	guint timer;
	int retry_count;
	int kick_count;
} proc_context;

typedef struct reply_info_s {
	pid_t pid;
	int fd;
	GIOChannel *io;
	guint watcher;
	guint timer;
} reply_info;

static watchdog __watchdog;

static void __watchdog_set_timer(proc_context *ctx);
static void __watchdog_unset_timer(proc_context *ctx);
static void __watchdog_set_retry_timer(proc_context *ctx);

static proc_context *__create_proc_context(pid_t pid, uid_t uid)
{
	proc_context *ctx;

	ctx = calloc(1, sizeof(proc_context));
	if (!ctx) {
		_E("Out of memory");
		return NULL;
	}

	ctx->pid = pid;
	ctx->uid = uid;

	return ctx;
}

static void __destroy_proc_context(gpointer data)
{
	proc_context *ctx = (proc_context *)data;

	if (!ctx) {
		_E("Critical error!");
		return;
	}

	if (ctx->timer > 0)
		g_source_remove(ctx->timer);

	free(ctx);
}

static proc_context *__find_proc_context(pid_t pid)
{
	proc_context *ctx;
	GList *iter;

	iter = __watchdog.proc_contexts;
	while (iter) {
		ctx = (proc_context *)iter->data;
		if (ctx && ctx->pid == pid)
			return ctx;

		iter = g_list_next(iter);
	}

	return NULL;
}

static reply_info *__create_reply_info(pid_t pid, int fd)
{
	reply_info *info;

	info = calloc(1, sizeof(reply_info));
	if (!info) {
		_E("Out of memory");
		return NULL;
	}

	info->pid = pid;
	info->fd = fd;

	return info;
}

static void __destroy_reply_info(gpointer data)
{
	reply_info *info = (reply_info *)data;

	if (!info)
		return;

	if (info->timer)
		g_source_remove(info->timer);

	if (info->watcher)
		g_source_remove(info->watcher);

	if (info->io)
		g_io_channel_unref(info->io);

	if (info->fd > 0)
		close(info->fd);

	free(info);
}

static const char *__get_appid(pid_t pid)
{
	amd_app_status_h app_status;
	const char *appid = NULL;

	app_status = amd_app_status_find_by_pid(pid);
	if (app_status)
		appid = amd_app_status_get_appid(app_status);

	return appid ? appid : "Unknown";
}

static void __check_retry_count(proc_context *ctx)
{
	if (ctx->retry_count == __watchdog.max_retry_count) {
		_E("Process(%d) will be terminated", ctx->pid);
		amd_signal_send_watchdog(ctx->pid, SIGKILL);
		_watchdog_logger_print("SIGKILL", "pid(%d), appid(%s)",
				ctx->pid, __get_appid(ctx->pid));
	} else {
		ctx->retry_count++;
		ctx->timer = 0;
		__watchdog_set_retry_timer(ctx);
		_W("retry count(%d), pid(%d)", ctx->retry_count, ctx->pid);
	}
}

static gboolean __watchdog_reply_timeout_handler(gpointer data)
{
	reply_info *info = (reply_info *)data;
	proc_context *ctx;

	if (!info) {
		_E("Critical error!");
		return G_SOURCE_REMOVE;
	}

	_W("Process(%d) is not responding", info->pid);
	_watchdog_logger_print("ANR", "pid(%d), appid(%s)",
			info->pid, __get_appid(info->pid));

	ctx = __find_proc_context(info->pid);
	if (!ctx) {
		_E("Failed to find process(%d) context", info->pid);
		goto end;
	}

	if (ctx->freeze) {
		_E("Process(%d) is freezed", info->pid);
		goto end;
	}

	__check_retry_count(ctx);
end:
	info->timer = 0;
	__destroy_reply_info(info);
	return G_SOURCE_REMOVE;
}

static gboolean __watchdog_reply_handler(GIOChannel *io, GIOCondition cond,
		gpointer data)
{
	reply_info *info = (reply_info *)data;
	proc_context *ctx;
	int r;

	if (!info) {
		_E("Critical error!");
		return G_SOURCE_REMOVE;
	}

	ctx = __find_proc_context(info->pid);
	if (!ctx) {
		_E("Failed to find proc context. pid(%d)", info->pid);
		info->watcher = 0;
		__destroy_reply_info(info);
		return G_SOURCE_REMOVE;
	}

	r = aul_sock_recv_result_with_fd(info->fd);
	if (r == 0) {
		ctx->retry_count = 0;
		ctx->kick_count = 0;
		if (!ctx->freeze)
			__watchdog_set_timer(ctx);
	} else {
		__check_retry_count(ctx);
	}
	_D("result: %d, pid: %d", r, ctx->pid);

	info->watcher = 0;
	__destroy_reply_info(info);
	return G_SOURCE_REMOVE;
}

static int __watchdog_set_reply_handler(pid_t pid, int fd)
{
	GIOCondition cond = G_IO_IN | G_IO_PRI | G_IO_ERR | G_IO_HUP;
	reply_info *info;

	info = __create_reply_info(pid, fd);
	if (!info) {
		_E("Failed to create reply info. pid(%d)", pid);
		close(fd);
		return -1;
	}

	info->io = g_io_channel_unix_new(fd);
	if (info->io == NULL) {
		_E("Failed to create gio channel. pid(%d)", pid);
		__destroy_reply_info(info);
		return -1;
	}

	info->watcher = g_io_add_watch(info->io, cond,
			__watchdog_reply_handler, info);
	if (info->watcher == 0) {
		_E("Failed to add gio watch. pid(%d)", pid);
		__destroy_reply_info(info);
		return -1;
	}

	info->timer = g_timeout_add(5000,
			__watchdog_reply_timeout_handler, info);
	if (info->timer == 0) {
		_E("Failed to add watchdog timer. pid(%d)", pid);
		__destroy_reply_info(info);
		return -1;
	}

	return 0;
}

static bundle *__create_bundle(void)
{
	struct timeval tv;
	char buf[64];
	bundle *b;
	int r;

	b = bundle_create();
	if (!b) {
		_E("Failed to create bundle");
		return NULL;
	}

	gettimeofday(&tv, NULL);
	snprintf(buf, sizeof(buf), "%ld/%ld", tv.tv_sec, tv.tv_usec);
	r = bundle_add(b, AUL_K_STARTTIME, buf);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add start time(%s)", buf);
		bundle_free(b);
		return NULL;
	}

	return b;
}

static int __watchdog_ping(proc_context *ctx)
{
	bundle *b;
	int fd;
	int r;

	b = __create_bundle();
	if (!b)
		return -1;

	fd = aul_sock_send_bundle(ctx->pid, ctx->uid,
			WATCHDOG_PING, b, AUL_SOCK_ASYNC);
	if (fd < 0) {
		_E("Failed to send ping request. pid(%d)", ctx->pid);
		bundle_free(b);
		return -1;
	}
	bundle_free(b);

	r = __watchdog_set_reply_handler(ctx->pid, fd);
	if (r < 0) {
		_E("Failed to set reply handler. pid(%d)", ctx->pid);
		return -1;
	}

	_I("Ping. pid(%d), fd(%d)", ctx->pid, fd);

	return 0;
}

static gboolean __watchdog_handler(gpointer data)
{
	proc_context *ctx = (proc_context *)data;
	int r;

	if (!ctx) {
		_E("Critical error!");
		return G_SOURCE_REMOVE;
	}

	r = __watchdog_ping(ctx);
	if (r < 0)
		__check_retry_count(ctx);
	else
		ctx->timer = 0;

	return G_SOURCE_REMOVE;
}

static void __watchdog_set_retry_timer(proc_context *ctx)
{
	if (!ctx->timer) {
		ctx->timer = g_timeout_add(100,
				__watchdog_handler, ctx);
	}
}

static void __watchdog_set_timer(proc_context *ctx)
{
	if (!ctx->timer) {
		ctx->timer = g_timeout_add(__watchdog.interval,
				__watchdog_handler, ctx);
	}
}

static void __watchdog_unset_timer(proc_context *ctx)
{
	if (ctx->timer) {
		g_source_remove(ctx->timer);
		ctx->timer = 0;
	}
}

static int __dispatch_watchdog_enable(amd_request_h req)
{
	int pid = amd_request_get_pid(req);
	proc_context *ctx;

	ctx = __find_proc_context(pid);
	if (!ctx) {
		_E("Failed to find process(%d) context", pid);
		amd_request_send_result(req, -1);
		return -1;
	}

	if (ctx->watchdog_enable) {
		_W("Watchdog timer is already enabled. pid(%d)", pid);
		amd_request_send_result(req, 0);
		return 0;
	}

	if (!ctx->freeze)
		__watchdog_set_timer(ctx);

	ctx->watchdog_enable = true;
	amd_request_send_result(req, 0);

	_I("pid(%d)", pid);
	_watchdog_logger_print("ENABLE", "pid(%d), appid(%s)",
			pid, __get_appid(pid));

	return 0;
}

static int __dispatch_watchdog_disable(amd_request_h req)
{
	int pid = amd_request_get_pid(req);
	proc_context *ctx;

	ctx = __find_proc_context(pid);
	if (!ctx) {
		_E("Failed to find process(%d) context", pid);
		amd_request_send_result(req, -1);
		return -1;
	}

	if (!ctx->watchdog_enable) {
		_W("Watchdog timer is already disabled. pid(%d)", pid);
		amd_request_send_result(req, 0);
		return 0;

	}

	__watchdog_unset_timer(ctx);

	ctx->watchdog_enable = false;
	ctx->retry_count = 0;
	ctx->kick_count = 0;
	amd_request_send_result(req, 0);

	_I("pid(%d)", pid);
	_watchdog_logger_print("DISABLE", "pid(%d), appid(%s)",
			pid, __get_appid(pid));

	return 0;
}

static int __dispatch_watchdog_kick(amd_request_h req)
{
	int pid = amd_request_get_pid(req);
	proc_context *ctx;

	ctx = __find_proc_context(pid);
	if (!ctx) {
		_E("Failed to find process(%d) context", pid);
		amd_request_send_result(req, -1);
		return -1;
	}

	if (!ctx->watchdog_enable) {
		_W("watchdog timer is not enabled. pid(%d)", pid);
		amd_request_send_result(req, -1);
		return -1;
	}

	__watchdog_unset_timer(ctx);
	__watchdog_set_timer(ctx);
	amd_request_send_result(req, 0);

	ctx->kick_count++;

	_I("pid(%d), kick count(%d)", pid, ctx->kick_count);
	_watchdog_logger_print("KICK", "count(%d), pid(%d), appid(%s)",
			ctx->kick_count, pid, __get_appid(pid));

	return 0;
}

static int __on_app_status_cleanup(const char *msg, int arg1, int arg2,
		void *arg3, bundle *b)
{
	int pid = arg1;
	proc_context *ctx;

	ctx = __find_proc_context(pid);
	if (!ctx) {
		_E("Failed to find process(%d) context", pid);
		return -1;
	}

	__watchdog.proc_contexts = g_list_remove(__watchdog.proc_contexts, ctx);
	__destroy_proc_context(ctx);

	return 0;
}

static int __on_app_status_add(const char *msg, int arg1, int arg2,
		void *arg3, bundle *b)
{
	amd_app_status_h app_status = (amd_app_status_h)arg3;
	int pid = amd_app_status_get_pid(app_status);
	uid_t uid;
	proc_context *ctx;
	int operation_state;

	ctx = __find_proc_context(pid);
	if (ctx) {
		_W("Process(%d) context already exists", pid);
		return -1;
	}

	uid = amd_app_status_get_uid(app_status);
	ctx = __create_proc_context(pid, uid);
	if (!ctx) {
		_E("Failed to create process(%d) context", pid);
		return -1;
	}

	__watchdog.proc_contexts = g_list_append(__watchdog.proc_contexts, ctx);

	operation_state = _watchdog_config_get_operation_state();
	if (operation_state == WATCHDOG_ENABLE_BY_DEFAULT) {
		__watchdog_set_timer(ctx);
		ctx->watchdog_enable = true;
		_watchdog_logger_print("ENABLE", "pid(%d), appid(%s)",
				pid, amd_app_status_get_appid(app_status));
	}

	return 0;
}

static amd_request_cmd_dispatch __dispatch_table[] = {
	{
		.cmd = WATCHDOG_ENABLE,
		.callback = __dispatch_watchdog_enable
	},
	{
		.cmd = WATCHDOG_DISABLE,
		.callback = __dispatch_watchdog_disable
	},
	{
		.cmd = WATCHDOG_KICK,
		.callback = __dispatch_watchdog_kick
	},
};

static void __on_freezer_state_changed(GDBusConnection *connection,
		const gchar *sender_name,
		const gchar *object_path,
		const gchar *interface_name,
		const gchar *signal_name,
		GVariant *parameters,
		gpointer user_data)
{
	gint pid = -1;
	gint status = -1;
	proc_context *ctx;

	if (!g_strcmp0(signal_name, RESOURCED_FREEZER_SIGNAL)) {
		g_variant_get(parameters, "(ii)", &status, &pid);
		ctx = __find_proc_context(pid);
		if (!ctx) {
			_E("Failed to find process(%d) context", pid);
			return;
		}

		/* 0: SET_FOREGRD, 1: SET_BACKGRD, */
		ctx->freeze = (bool)status;
		if (ctx->freeze) {
			__watchdog_unset_timer(ctx);
		} else {
			if (ctx->watchdog_enable)
				__watchdog_set_timer(ctx);
		}

		_W("pid(%d), freezer state(%s)",
				pid, status ? "BACKGRD" : "FOREGRD");
		_watchdog_logger_print("FREEZER",
				"state(%s), pid(%d), appid(%s)",
				status ? "BACKGRD" : "FOREGRD",
				pid, __get_appid(pid));
	}
}

static int __listen_freezer_state(void)
{
	GError *err = NULL;

	if (__watchdog.listener)
		return 0;

	if (!__watchdog.conn) {
		__watchdog.conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (!__watchdog.conn) {
			_E("Failed to connecto D-Bus daemon. err(%s)",
					err->message);
			g_error_free(err);
			return -1;
		}
	}

	__watchdog.listener = g_dbus_connection_signal_subscribe(
			__watchdog.conn,
			NULL,
			RESOURCED_FREEZER_INTERFACE,
			RESOURCED_FREEZER_SIGNAL,
			RESOURCED_FREEZER_PATH,
			NULL,
			G_DBUS_SIGNAL_FLAGS_NONE,
			__on_freezer_state_changed,
			NULL,
			NULL);
	if (!__watchdog.listener) {
		_E("Failed to subscribe freezer state");
		return -1;
	}

	_I("%s is subscribed", RESOURCED_FREEZER_SIGNAL);

	return 0;
}

static gboolean __retry_dbus_connection(gpointer data)
{
	static int retry_count;
	int r;

	_W("Retry count: %d", retry_count++);
	r = __listen_freezer_state();
	if (r != 0)
		return G_SOURCE_CONTINUE;

	__watchdog.retry_handler = 0;
	return G_SOURCE_REMOVE;
}

static void __ignore_freezer_state(void)
{
	if (!__watchdog.conn)
		return;

	if (__watchdog.listener) {
		g_dbus_connection_signal_unsubscribe(__watchdog.conn,
				__watchdog.listener);
		__watchdog.listener = 0;
	}

	g_object_unref(__watchdog.conn);
	__watchdog.conn = NULL;
}

EXPORT int AMD_MOD_INIT(void)
{
	int r;

	_D("init");

	_watchdog_logger_init();
	_watchdog_config_init();

	__watchdog.interval = _watchdog_config_get_interval();
	__watchdog.max_retry_count = _watchdog_config_get_max_retry_count();

	r = amd_request_register_cmds(__dispatch_table,
			ARRAY_SIZE(__dispatch_table));
	if (r < 0) {
		_E("Failed to register cmds");
		return -1;
	}

	amd_noti_listen("app_status.add", __on_app_status_add);
	amd_noti_listen("app_status.cleanup", __on_app_status_cleanup);

	r = __listen_freezer_state();
	if (r != 0) {
		__watchdog.retry_handler = g_timeout_add(3000,
				__retry_dbus_connection, NULL);
	}

	return 0;
}

EXPORT void AMD_MOD_FINI(void)
{
	_D("fini");

	if (__watchdog.retry_handler)
		g_source_remove(__watchdog.retry_handler);

	__ignore_freezer_state();

	if (__watchdog.proc_contexts) {
		g_list_free_full(__watchdog.proc_contexts,
				__destroy_proc_context);
	}

	_watchdog_config_fini();
	_watchdog_logger_fini();
}
