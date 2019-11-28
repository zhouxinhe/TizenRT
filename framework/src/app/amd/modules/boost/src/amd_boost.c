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
#include <ctype.h>
#include <glib.h>
#include <gio/gio.h>
#include <amd.h>
#include <vconf.h>
#include <aul_cmd.h>
#include <aul_svc_priv_key.h>
#include <bundle_internal.h>

#include "amd_boost_private.h"

#define PASS_BUS_NAME			"org.tizen.system.pass"
#define PASS_PATH_PMQOS			"/Org/Tizen/System/Pass/Pmqos"
#define PASS_INTERFACE_PMQOS		"org.tizen.system.pass.pmqos"
#define PASS_METHOD_APPLAUNCH		"AppLaunch"

#define APP_BOOSTING_PERIOD		1500
#define APP_BOOSTING_STOP		0

#define APP_CONTROL_OPERATION_MAIN \
	"http://tizen.org/appcontrol/operation/main"

static GDBusConnection *__system_conn;

static GDBusConnection *__get_system_conn(void)
{
	GError *err = NULL;

	if (__system_conn)
		return __system_conn;

	__system_conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
	if (__system_conn == NULL) {
		_E("g_bus_get_sync() is failed: %s", err->message);
		g_error_free(err);
		return NULL;
	}

	return __system_conn;
}

static int __send_cpu_boost_request(int req)
{
	GError *err = NULL;
	GDBusMessage *msg;
	GDBusConnection *conn;
	int res = 0;

	conn = __get_system_conn();
	if (conn == NULL)
		return -1;

	msg = g_dbus_message_new_method_call(PASS_BUS_NAME,
			PASS_PATH_PMQOS,
			PASS_INTERFACE_PMQOS,
			PASS_METHOD_APPLAUNCH);
	if (msg == NULL) {
		_E("g_dbus_message_new_method_call() is failed.");
		return -1;
	}

	g_dbus_message_set_body(msg, g_variant_new("(i)", req));
	if (g_dbus_connection_send_message(conn,
				msg,
				G_DBUS_SEND_MESSAGE_FLAGS_NONE,
				NULL,
				&err) == FALSE) {
		_E("g_dbus_connection_send_message() is failed(%s)",
				err->message);
		res = -1;
	}

	g_dbus_connection_flush(conn, NULL, NULL, NULL);
	g_object_unref(msg);
	g_clear_error(&err);

	_D("send cpu boost req(%d)", req);

	return res;
}

static int __on_start(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	__send_cpu_boost_request(APP_BOOSTING_PERIOD);
	return 0;
}

static int __on_cancel(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	__send_cpu_boost_request(APP_BOOSTING_STOP);
	return 0;
}

static int __on_launch(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	__send_cpu_boost_request(APP_BOOSTING_STOP);
	return 0;
}

static int __on_relaunch_start(const char *msg, int arg1, int arg2,
		void *arg3, bundle *kb)
{
	int cmd = arg1;
	const char *op;
	int lcd_status = 0;

	op = bundle_get_val(kb, AUL_SVC_K_OPERATION);
	if ((op && !strcmp(op, APP_CONTROL_OPERATION_MAIN)) ||
			cmd == APP_OPEN) {
		vconf_get_int(VCONFKEY_PM_STATE, &lcd_status);
		if (lcd_status == VCONFKEY_PM_STATE_LCDOFF)
			_D("LCD OFF: Skip app launch boost");
		else
			__send_cpu_boost_request(APP_BOOSTING_PERIOD);
	}

	return 0;
}

EXPORT int AMD_MOD_INIT(void)
{
	_D("boost init");

	amd_noti_listen("launch.do_starting_app.start", __on_start);
	amd_noti_listen("launch.do_starting_app.cancel", __on_cancel);
	amd_noti_listen("launch.status.launch", __on_launch);
	amd_noti_listen("launch.do_starting_app.relaunch.start",
			__on_relaunch_start);

	return 0;
}

EXPORT void AMD_MOD_FINI(void)
{
	_D("boost finish");

	if (__system_conn) {
		g_object_unref(__system_conn);
		__system_conn = NULL;
	}
}
