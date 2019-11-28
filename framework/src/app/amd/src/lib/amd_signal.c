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
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <gio/gio.h>
#include <glib.h>

#include "app_signal.h"
#include "amd_util.h"
#include "amd_signal.h"
#include "amd_noti.h"

#define MAX_LABEL_BUFSZ 1024
#define SIGNAL_INIT_INTERVAL 3

struct signal_initializer {
	int (*callback)(void *data);
	void *data;
};

static GDBusConnection *system_conn;
static GList *signal_init_list;
static guint startup_finished_sid;
static guint user_session_startup_finished_sid;
static int (*startup_finished_callback)(uid_t, void *);
static void *startup_finished_data;
static uid_t startup_finished_uid;
static bool system_boot_completed;
static bool user_boot_completed;
static guint poweroff_state_sid;
static void (*poweroff_state_callback)(int, void *);
static void *poweroff_state_data;

static GDBusConnection *__get_system_conn(void)
{
	GError *err = NULL;

	if (system_conn)
		return system_conn;

	system_conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
	if (system_conn == NULL) {
		_E("g_bus_get_sync() is failed: %s", err->message);
		g_error_free(err);
		return NULL;
	}

	return system_conn;
}

static int __send_signal(const char *object_path, const char *interface_name,
		const char *signal_name, GVariant *parameters)
{
	GError *err = NULL;
	GDBusConnection *conn;

	conn = __get_system_conn();
	if (conn == NULL)
		return -1;

	if (g_dbus_connection_emit_signal(conn,
					NULL,
					object_path,
					interface_name,
					signal_name,
					parameters,
					&err) == FALSE) {
		_E("g_dbus_connection_emit_signal() is failed: %s",
					err->message);
		g_error_free(err);
		return -1;
	}

	if (g_dbus_connection_flush_sync(conn, NULL, &err) == FALSE) {
		_E("g_dbus_connection_flush_sync() is failed: %s",
				err->message);
		g_error_free(err);
		return -1;
	}

	return 0;
}

int _signal_send_watchdog(int pid, int signal_num)
{
	int r;
	GVariant *param;

	if (_noti_send("signal.send_watchdog.start", 0, 0, NULL, NULL) < 0) {
		_E("Some listeners don't want to continue (pid:%d)", pid);
		return -1;
	}

	param = g_variant_new("(ii)", pid, signal_num);
	if (!param) {
		_E("Out of memory");
		return -1;
	}

	r = __send_signal(RESOURCED_PROC_OBJECT,
			RESOURCED_PROC_INTERFACE,
			RESOURCED_PROC_WATCHDOG_SIGNAL,
			param);
	if (r < 0) {
		_E("Failed to send a watchdog signal - pid(%d)", pid);
		return -1;
	}

	_W("Send a watchdog signal done - pid(%d)", pid);

	return 0;
}

int _signal_send_proc_prelaunch(const char *appid, const char *pkgid,
		int attribute, int category)
{
	int r;
	GVariant *param;

	param = g_variant_new("(ssii)", appid, pkgid, attribute, category);
	if (!param) {
		_E("Out of memory");
		return -1;
	}

	r = __send_signal(RESOURCED_PROC_OBJECT,
			RESOURCED_PROC_INTERFACE,
			RESOURCED_PROC_PRELAUNCH_SIGNAL,
			param);
	if (r < 0) {
		_E("Failed to send a prelaunch signal - appid(%s)", appid);
		return -1;
	}

	_W("send a prelaunch signal done: " \
			"appid(%s) pkgid(%s) attribute(%x) category(%x)",
			appid, pkgid, attribute, category);

	return 0;
}

int _signal_send_tep_mount(char *mnt_path[], const char *pkgid)
{
	GError *err = NULL;
	GDBusMessage *msg;
	GDBusConnection *conn;
	int ret = 0;
	int rv = 0;
	struct stat link_buf = {0,};
	GVariant *param;
	char buf[MAX_LABEL_BUFSZ];

	if (pkgid == NULL) {
		_E("Invalid parameter");
		return -1;
	}

	conn = __get_system_conn();
	if (conn == NULL)
		return -1;

	rv = lstat(mnt_path[0], &link_buf);
	if (rv == 0) {
		rv = unlink(mnt_path[0]);
		if (rv)
			_E("Unable tp remove link file %s", mnt_path[0]);
	}

	msg = g_dbus_message_new_method_call(TEP_BUS_NAME,
					TEP_OBJECT_PATH,
					TEP_INTERFACE_NAME,
					TEP_MOUNT_METHOD);
	if (msg == NULL) {
		_E("g_dbus_message_new_method_call() is failed.");
		return -1;
	}

	snprintf(buf, sizeof(buf), "User::Pkg::%s::RO", pkgid);
	param = g_variant_new("(sss)", mnt_path[0], mnt_path[1], buf);
	g_dbus_message_set_body(msg, param);

	if (g_dbus_connection_send_message(conn,
					msg,
					G_DBUS_SEND_MESSAGE_FLAGS_NONE,
					NULL,
					&err) == FALSE) {
		_E("g_dbus_connection_send_message() is failed: %s",
					err->message);
		ret = -1;
	}

	if (g_dbus_connection_flush_sync(conn, NULL, &err) == FALSE) {
		_E("g_dbus_connection_flush_sync() is failed: %s",
					err->message);
		ret = -1;
	}

	g_object_unref(msg);
	g_clear_error(&err);

	return ret;
}

int _signal_send_tep_unmount(const char *mnt_path)
{
	GError *err = NULL;
	GDBusMessage *msg;
	GDBusConnection *conn;

	conn = __get_system_conn();
	if (conn == NULL)
		return -1;

	msg = g_dbus_message_new_method_call(TEP_BUS_NAME,
					TEP_OBJECT_PATH,
					TEP_INTERFACE_NAME,
					TEP_UNMOUNT_METHOD);
	if (msg == NULL) {
		_E("g_dbus_message_new_method_call() is failed.");
		return -1;
	}

	g_dbus_message_set_body(msg, g_variant_new("(s)", mnt_path));
	if (g_dbus_connection_send_message(conn,
					msg,
					G_DBUS_SEND_MESSAGE_FLAGS_NONE,
					NULL,
					&err) == FALSE) {
		_E("g_dbus_connection_send_message() is failed: %s",
					err->message);
		g_object_unref(msg);
		g_clear_error(&err);
		return -1;
	}

	g_dbus_connection_flush(conn, NULL, NULL, NULL);
	g_object_unref(msg);
	g_clear_error(&err);

	return 0;
}

int _signal_send_proc_suspend(int pid)
{
	GError *err = NULL;
	GDBusConnection *conn;

	conn = __get_system_conn();
	if (conn == NULL)
		return -1;

	if (g_dbus_connection_emit_signal(conn,
					NULL,
					APPFW_SUSPEND_HINT_PATH,
					APPFW_SUSPEND_HINT_INTERFACE,
					APPFW_SUSPEND_HINT_SIGNAL,
					g_variant_new("(i)", pid),
					&err) == FALSE) {
		_E("g_dbus_connection_emit_signal() is failed: %s",
					err->message);
		g_error_free(err);
		return -1;
	}

	if (g_dbus_connection_flush_sync(conn, NULL, &err) == FALSE) {
		_E("g_dbus_connection_flush_sync() is failed: %s",
					err->message);
		g_error_free(err);
		return -1;
	}

	_D("[__SUSPEND__] Send suspend hint, pid: %d", pid);

	return 0;
}

int _signal_get_proc_status(const int pid, int *status, int *focused)
{
	GError *err = NULL;
	GDBusMessage *message;
	GDBusMessage *reply;
	GVariant *var;
	GDBusConnection *conn;
	int proc_status = -1;
	int proc_focus = -1;

	conn = __get_system_conn();
	if (conn == NULL)
		return -1;

	message = g_dbus_message_new_method_call(WM_PROC_NAME,
					WM_PROC_PATH,
					WM_PROC_INTERFACE,
					WM_PROC_METHOD);
	if (message == NULL) {
		_E("g_bus_message_new_method_call() is failed.");
		return -1;
	}

	g_dbus_message_set_body(message, g_variant_new("(i)", pid));
	reply = g_dbus_connection_send_message_with_reply_sync(conn,
					message,
					G_DBUS_SEND_MESSAGE_FLAGS_NONE,
					-1,
					NULL,
					NULL,
					&err);
	g_dbus_connection_flush(conn, NULL, NULL, NULL);
	g_object_unref(message);
	if (reply == NULL) {
		_E("Failed to send message with reply sync: %s", err->message);
		g_clear_error(&err);
		return -1;
	}

	var = g_dbus_message_get_body(reply);
	if (var == NULL) {
		_E("g_dbus_message_get_body() is failed");
		g_object_unref(reply);
		return -1;
	}
	g_variant_get(var, "(ii)", &proc_status, &proc_focus);

	g_object_unref(reply);

	if (proc_status == -1 || proc_focus == -1) {
		_E("Failed to get proc status info");
		return -1;
	}

	*status = proc_status;
	*focused = proc_focus;
	_D("pid(%d), status(%d), focused(%d)", pid, proc_status, proc_focus);

	return 0;
}

static void __system_bus_signal_handler(GDBusConnection *connection,
		const gchar *sender_name, const gchar *object_path,
		const gchar *interface_name, const char *signal_name,
		GVariant *parameters, gpointer user_data)
{
	guint64 uid = 0;
	int state = -1;

	_W("[SIGNAL_HANDLER] signal(%s)", signal_name);
	if (g_strcmp0(signal_name, SD_STARTUP_FINISHED_SIGNAL) == 0) {
		system_boot_completed = true;
		_D("[SIGNAL_HANDLER] system boot completed");
	} else if (g_strcmp0(signal_name,
			SD_USER_SESSION_STARTUP_FINISHED_SIGNAL) == 0) {
		user_boot_completed = true;
		g_variant_get(parameters, "(t)", &uid);
		startup_finished_uid = (uid_t)uid;
		_D("[SIGNAL_HANDLER] user boot completed");
	} else if (g_strcmp0(signal_name, SYSTEM_POWEROFF_STATE_SIGNAL) == 0) {
		g_variant_get(parameters, "(i)",  &state);
		if (poweroff_state_callback)
			poweroff_state_callback(state, poweroff_state_data);
		_D("[SIGNAL_HANDLER] poweroff state(%d)", state);
	}

	if (system_boot_completed && user_boot_completed) {
		if (startup_finished_callback) {
			startup_finished_callback(startup_finished_uid,
					startup_finished_data);
		}

		user_boot_completed = false;
	}
}

static guint __subscribe_system_bus(const char *object_path,
		const char *interface_name, const char *signal_name)
{
	guint sid;
	GError *err = NULL;
	GDBusConnection *conn;

	conn = __get_system_conn();
	if (conn == NULL)
		return 0;

	sid = g_dbus_connection_signal_subscribe(conn,
						NULL,
						interface_name,
						signal_name,
						object_path,
						NULL,
						G_DBUS_SIGNAL_FLAGS_NONE,
						__system_bus_signal_handler,
						NULL,
						NULL);
	if (sid == 0)
		_E("g_bus_connection_signal_subscribe() is failed");

	g_clear_error(&err);

	return sid;
}

int _signal_subscribe_startup_finished(int (*callback)(uid_t uid, void *data),
		void *user_data)
{
	if (callback == NULL)
		return -1;

	startup_finished_sid = __subscribe_system_bus(SD_OBJECT_PATH,
			SD_MANAGER_INTERFACE,
			SD_STARTUP_FINISHED_SIGNAL);
	if (startup_finished_sid == 0) {
		_E("Failed to subscribe systemd signal");
		return -1;
	}

	user_session_startup_finished_sid = __subscribe_system_bus(
			SD_OBJECT_PATH,
			SD_MANAGER_INTERFACE,
			SD_USER_SESSION_STARTUP_FINISHED_SIGNAL);
	if (user_session_startup_finished_sid == 0) {
		_E("Failed to subscribe systemd signal");
		_signal_unsubscribe_startup_finished();
		return -1;
	}

	startup_finished_callback = callback;
	startup_finished_data = user_data;
	_D("[SIGNAL] subscribe startup finished");

	return 0;
}

int _signal_unsubscribe_startup_finished(void)
{
	GDBusConnection *conn;

	conn = __get_system_conn();
	if (conn == NULL)
		return -1;

	if (!startup_finished_sid && !user_session_startup_finished_sid)
		return 0;

	if (startup_finished_sid) {
		g_dbus_connection_signal_unsubscribe(conn,
				startup_finished_sid);
		startup_finished_sid = 0;
	}

	if (user_session_startup_finished_sid) {
		g_dbus_connection_signal_unsubscribe(conn,
				user_session_startup_finished_sid);
		user_session_startup_finished_sid = 0;
	}

	startup_finished_callback = NULL;
	startup_finished_data = NULL;
	_D("[SIGNAL] unsubscribe startup finished");

	return 0;
}

int _signal_send_display_lock_state(const char *state, const char *flag,
		unsigned int timeout)
{
	GError *err = NULL;
	GDBusConnection *conn;
	GDBusMessage *msg;
	const char *holdkeyblock_string = "holdkeyblock";
	int ret = 0;

	_D("Acquring display lock");
	conn = __get_system_conn();
	if (conn == NULL)
		return -1;

	msg = g_dbus_message_new_method_call(SYSTEM_BUS_NAME,
			SYSTEM_PATH_DISPLAY,
			SYSTEM_INTERFACE_DISPLAY,
			SYSTEM_LOCK_STATE);
	if (msg == NULL) {
		_E("g_dbus_message_new_method_call() is failed");
		return -1;
	}

	g_dbus_message_set_body(msg, g_variant_new("(sssi)", state,
			flag, holdkeyblock_string, timeout));
	if (!g_dbus_connection_send_message(conn, msg,
				G_DBUS_SEND_MESSAGE_FLAGS_NONE, NULL, &err)) {
		_E("Unable to send dbus message for acquring lock as  %s",
				err->message);
		ret = -1;
	}

	_D("Display lock acquired");
	g_object_unref(msg);
	g_dbus_connection_flush_sync(conn, NULL, NULL);
	g_clear_error(&err);
	return ret;
}

int _signal_send_display_unlock_state(const char *state, const char *flag)
{
	GError *err = NULL;
	GDBusConnection *conn;
	GDBusMessage *msg;
	int ret = 0;

	_D("releasing display lock");
	conn = __get_system_conn();
	if (conn == NULL)
		return -1;

	msg = g_dbus_message_new_method_call(SYSTEM_BUS_NAME,
			SYSTEM_PATH_DISPLAY,
			SYSTEM_INTERFACE_DISPLAY,
			SYSTEM_UNLOCK_STATE);
	if (msg == NULL) {
		_E("g_dbus_message_new_method_call() is failed");
		return -1;
	}

	g_dbus_message_set_body(msg, g_variant_new("(ss)", state, flag));
	if (!g_dbus_connection_send_message(conn, msg,
				G_DBUS_SEND_MESSAGE_FLAGS_NONE, NULL, &err)) {
		_E("Unable to send dbus message for releasing lock as  %s",
			err->message);
		ret = -1;
	}

	_D("Display lock released");
	g_object_unref(msg);
	g_dbus_connection_flush_sync(conn, NULL, NULL);
	g_clear_error(&err);
	return ret;
}

int _signal_send_system_service(int pid)
{
	int r;
	GVariant *param;

	param = g_variant_new("(i)", pid);
	if (!param) {
		_E("Out of memory");
		return -1;
	}

	r = __send_signal(RESOURCED_PROC_OBJECT,
			RESOURCED_PROC_INTERFACE,
			RESOURCED_SYSTEM_SERVICE_SIGNAL,
			param);
	if (r < 0) {
		_E("Failed to send system service signal - pid(%d)", pid);
		return -1;
	}

	_D("Send system service signal: pid(%d)", pid);

	return 0;
}

int _signal_subscribe_poweroff_state(void (*callback)(int state, void *data),
		void *user_data)
{
	if (callback == NULL)
		return -1;

	poweroff_state_sid = __subscribe_system_bus(SYSTEM_PATH_POWEROFF,
			SYSTEM_INTERFACE_POWEROFF,
			SYSTEM_POWEROFF_STATE_SIGNAL);
	if (poweroff_state_sid == 0) {
		_E("Failed to subscribe poweroff state signal");
		return -1;
	}

	poweroff_state_callback = callback;
	poweroff_state_data = user_data;
	_D("[SIGNAL] subscribe poweroff state");

	return 0;
}

int _signal_add_initializer(int (*callback)(void *data), void *user_data)
{
	struct signal_initializer *initializer;

	if (callback == NULL) {
		_E("Invalid parameter");
		return -1;
	}

	initializer = (struct signal_initializer *)malloc(
			sizeof(struct signal_initializer));
	if (initializer == NULL) {
		_E("out of memory");
		return -1;
	}

	initializer->callback = callback;
	initializer->data = user_data;

	signal_init_list = g_list_append(signal_init_list, initializer);

	return 0;
}

static gboolean __dispatch_initializer_list(gpointer user_data)
{
	struct signal_initializer *initializer;
	GList *list;
	int ret;

	list = g_list_first(signal_init_list);
	while (list) {
		initializer = (struct signal_initializer *)list->data;
		list = g_list_next(list);
		if (initializer) {
			ret = initializer->callback(initializer->data);
			if (ret == 0) {
				signal_init_list =
					g_list_remove(signal_init_list,
							initializer);
				free(initializer);
			}
		}
	}

	if (signal_init_list == NULL) {
		_D("init list is NULL");
		return FALSE;
	}

	return TRUE;
}

int _signal_init(void)
{
	if (signal_init_list) {
		g_timeout_add_seconds(SIGNAL_INIT_INTERVAL,
				__dispatch_initializer_list, NULL);
	}

	return 0;
}
