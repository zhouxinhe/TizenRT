/*
 * Copyright (c) 2017 Samsung Electronics Co., Ltd. All rights reserved.
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
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <gio/gio.h>
#include <glib.h>
#include <malloc.h>

#include "aul.h"
#include "launch.h"
#include "aul_api.h"
#include "aul_util.h"
#include "aul_window.h"
#include "aul_cmd.h"

static GDBusConnection *system_conn;

#define WM_BUS_NAME	"org.enlightenment.wm"
#define WM_OBJECT_PATH	"/org/enlightenment/wm"
#define WM_INTERFACE_NAME	"org.enlightenment.wm.proc"
#define WM_METHOD_NAME_INFO	"GetVisibleWinInfo"
#define WM_METHOD_NAME_FOCUS	"GetFocusProc"


typedef struct _window_info {
	unsigned int gid;
	int x;
	int y;
	int w;
	int h;
	gboolean alpha;
	int visibility;
	gboolean focused;
	int pid;
	int ppid;
	int apid;
	int noti_level;
	gboolean opaque;
} window_info;

API int aul_window_stack_get(aul_window_stack_h *handle)
{
	GError *err = NULL;
	GDBusMessage *msg;
	GDBusMessage *reply;
	GDBusConnection *conn;
	int res = 0;
	window_info *wi;
	GVariant *body;
	GVariantIter *iter = NULL;
	GList *list = NULL;

	if (system_conn == NULL) {
		conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (conn == NULL) {
			_E("g_bus_get_sync() is failed. %s", err->message);
			g_error_free(err);
			return -1;
		}
		system_conn = conn;
	}

	msg = g_dbus_message_new_method_call(WM_BUS_NAME,
						WM_OBJECT_PATH,
						WM_INTERFACE_NAME,
						WM_METHOD_NAME_INFO);
	if (msg == NULL) {
		_E("g_dbus_message_new_method_call() is failed.");
		return -1;
	}

	reply = g_dbus_connection_send_message_with_reply_sync(system_conn, msg,
			G_DBUS_SEND_MESSAGE_FLAGS_NONE, -1, NULL, NULL, &err);

	if (!reply) {
		if (err != NULL) {
			_E("Failed to get info [%s]", err->message);
			g_error_free(err);
		}
		res = -1;
		goto out;
	}

	body = g_dbus_message_get_body(reply);
	if (!body) {
		res = -1;
		goto out;
	}

	wi = malloc(sizeof(window_info));
	if (wi == NULL) {
		_E("Out of memory");
		res = -1;
		goto out;
	}

	g_variant_get(body, "(a(uiiiibibiiiib))", &iter);
	while (iter && g_variant_iter_loop(iter, "(uiiiibibiiiib)",
			&wi->gid,
			&wi->x,
			&wi->y,
			&wi->w,
			&wi->h,
			&wi->alpha,
			&wi->visibility,
			&wi->focused,
			&wi->pid,
			&wi->ppid,
			&wi->apid,
			&wi->noti_level,
			&wi->opaque)) {
		list = g_list_append(list, wi);
		wi = malloc(sizeof(window_info));
	}

	free(wi);
	if (iter)
		g_variant_iter_free(iter);
	*handle = list;
out:
	if (msg)
		g_object_unref(msg);
	if (reply)
		g_object_unref(reply);

	return res;
}

static void __free_info(gpointer data)
{
	free(data);
}

API int aul_window_stack_del(aul_window_stack_h handle)
{
	if (!handle)
		return -1;

	g_list_free_full(handle, __free_info);
	return 0;
}

API int aul_window_stack_foreach(aul_window_stack_h handle,
		void (*iter_cb)(aul_window_info_h info, void *data), void *data)
{
	GList *i = (GList*)handle;

	if (!iter_cb || !handle)
		return -1;

	while (i) {
		iter_cb(i->data, data);
		i = g_list_next(i);
	}

	return 0;
}

API int aul_window_stack_info_get_resource_id(aul_window_info_h info, unsigned int *rid)
{
	window_info *wi = info;

	if (!info || !rid)
		return -1;

	*rid = wi->gid;
	return 0;
}

API int aul_window_info_get_pid(aul_window_info_h info, int *pid)
{
	window_info *wi = info;

	if (!info || !pid)
		return -1;

	*pid = wi->pid;
	return 0;
}

API int aul_window_info_get_parent_pid(aul_window_info_h info, int *ppid)
{
	window_info *wi = info;

	if (!info || !ppid)
		return -1;

	*ppid = wi->ppid;
	return 0;
}

API int aul_window_info_get_ancestor_pid(aul_window_info_h info, int *apid)
{
	window_info *wi = info;

	if (!info || !apid)
		return -1;

	*apid = wi->apid;
	return 0;
}

API int aul_window_info_get_visibility(aul_window_info_h info, int *visibility)
{
	window_info *wi = info;

	if (!info || !visibility)
		return -1;

	*visibility = wi->visibility;
	return 0;
}

API int aul_window_info_has_alpha(aul_window_info_h info, bool *alpha)
{
	window_info *wi = info;

	if (!info || !alpha)
		return -1;

	*alpha = (bool)(wi->alpha);
	return 0;
}

API int aul_window_info_is_focused(aul_window_info_h info, bool *focused)
{
	window_info *wi = info;

	if (!info || !focused)
		return -1;

	*focused = (bool)(wi->focused);
	return 0;
}

API int aul_window_info_get_geometry(aul_window_info_h info, int *x, int *y, int *w, int *h)
{
	window_info *wi = info;

	if (!info || !x || !y || !w || !h)
		return -1;

	*x = wi->x;
	*y = wi->y;
	*w = wi->w;
	*h = wi->h;
	return 0;
}

API int aul_window_info_get_notification_level(aul_window_info_h info,
		aul_window_notification_level_e *level)
{
	window_info *wi = info;

	if (!info || !level)
		return -1;

	*level = (aul_window_notification_level_e)wi->noti_level;

	return 0;
}

API int aul_window_get_focused_pid(pid_t *pid)
{
	GError *err = NULL;
	GDBusMessage *msg;
	GDBusMessage *reply;
	GDBusConnection *conn;
	int res = 0;
	GVariant *body;
	gint32 focused_pid = 0;

	if (!pid) {
		_E("aul_window_get_focused_pid: argument 'pid' cannot be NULL.");
		return -1;
	}

	_W("call aul_window_get_focused_pid()");
	if (system_conn == NULL) {
		conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (conn == NULL) {
			_E("g_bus_get_sync() is failed. %s", err->message);
			g_error_free(err);
			return -1;
		}
		system_conn = conn;
	}

	msg = g_dbus_message_new_method_call(WM_BUS_NAME,
						WM_OBJECT_PATH,
						WM_INTERFACE_NAME,
						WM_METHOD_NAME_FOCUS);
	if (msg == NULL) {
		_E("g_dbus_message_new_method_call() is failed.");
		return -1;
	}

	reply = g_dbus_connection_send_message_with_reply_sync(system_conn, msg,
			G_DBUS_SEND_MESSAGE_FLAGS_NONE, -1, NULL, NULL, &err);

	if (!reply) {
		_E("reply is null");
		if (err != NULL) {
			_E("Failed to get info [%s]", err->message);
			g_error_free(err);
		}
		res = -1;
		goto out;
	}

	body = g_dbus_message_get_body(reply);
	if (!body) {
		res = -1;
		_E("Body is null");
		goto out;
	}

	g_variant_get(body, "(i)", &focused_pid);
	*pid = (pid_t)focused_pid;
	_W("result = %d", focused_pid);
out:
	if (msg)
		g_object_unref(msg);
	if (reply)
		g_object_unref(reply);

	return res;
}

API int aul_window_attach(const char *parent_appid, const char *child_appid)
{
	bundle *b;
	int ret;

	if (parent_appid == NULL || child_appid == NULL)
		return -1;

	b = bundle_create();
	if (!b) {
		_E("out of memory");
		return -1;
	}

	bundle_add_str(b, AUL_K_PARENT_APPID, parent_appid);
	bundle_add_str(b, AUL_K_CHILD_APPID, child_appid);

	ret = app_send_cmd(AUL_UTIL_PID, APP_WINDOW_ATTACH, b);
	bundle_free(b);

	return ret;
}

API int aul_window_detach(const char *child_appid)
{
	bundle *b;
	int ret;

	if (child_appid == NULL)
		return -1;

	b = bundle_create();
	if (!b) {
		_E("out of memory");
		return -1;
	}

	bundle_add_str(b, AUL_K_CHILD_APPID, child_appid);

	ret = app_send_cmd(AUL_UTIL_PID, APP_WINDOW_DETACH, b);
	bundle_free(b);

	return ret;
}

API int aul_window_info_get_opaque(aul_window_info_h info, bool *opaque)
{
	window_info *wi = info;

	if (!info || !opaque) {
		_E("Invalid parameter");
		return -1;
	}

	*opaque = (bool)wi->opaque;
	return 0;
}
