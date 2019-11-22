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
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <linux/limits.h>

#include <Ecore_Wl2.h>
#include <glib-object.h>
#include <malloc.h>
#include <glib.h>
#include <gio/gio.h>
#include <stdbool.h>
#include <aul.h>
#include <aul_svc.h>
#include <bundle_internal.h>

#include "appcore_base.h"
#include "appcore_multiwindow_base.h"
#include "appcore_multiwindow_base_private.h"

appcore_multiwindow_base_context _appcore_mw_context;
static guint __flush_timer = 0;

static gboolean __flush_memory(gpointer data)
{
	_DBG("Flush memory");
	if (_appcore_mw_context.ops.base.trim_memory)
		_appcore_mw_context.ops.base.trim_memory(_appcore_mw_context.data);
	__flush_timer = 0;
	return G_SOURCE_REMOVE;
}

static void __add_flush_timer(void)
{
	if (__flush_timer)
		return;

	__flush_timer = g_timeout_add(5000, __flush_memory, NULL);
}

static void __remove_flush_timer(void)
{
	if (!__flush_timer)
		return;

	g_source_remove(__flush_timer);
	__flush_timer = 0;
}

static Eina_Bool __stub_show_cb(void *data, int type, void *event)
{
	if (_appcore_mw_context.ops.window.show)
		_appcore_mw_context.ops.window.show(type, event, _appcore_mw_context.data);

	return ECORE_CALLBACK_RENEW;
}

static Eina_Bool __stub_hide_cb(void *data, int type, void *event)
{
	if (_appcore_mw_context.ops.window.hide)
		_appcore_mw_context.ops.window.hide(type, event, _appcore_mw_context.data);

	return ECORE_CALLBACK_RENEW;
}

static Eina_Bool __stub_visibility_cb(void *data, int type, void *event)
{
	Ecore_Wl2_Event_Window_Visibility_Change *ev = event;

	if (_appcore_mw_context.ops.window.visibility)
		_appcore_mw_context.ops.window.visibility(type, event, _appcore_mw_context.data);

	if (ev && ev->fully_obscured) {
		if (!appcore_multiwindow_base_window_is_resumed())
			__add_flush_timer();
	} else {
		__remove_flush_timer();
	}

	return ECORE_CALLBACK_RENEW;
}

static Eina_Bool __stub_lower_cb(void *data, int type, void *event)
{
	if (_appcore_mw_context.ops.window.lower)
		_appcore_mw_context.ops.window.lower(type, event, _appcore_mw_context.data);

	return ECORE_CALLBACK_RENEW;
}

static Eina_Bool __stub_pre_visibility_cb(void *data, int type, void *event)
{
	Ecore_Wl2_Event_Window_Pre_Visibility_Change *ev = event;

	if (_appcore_mw_context.ops.window.pre_visibility)
		_appcore_mw_context.ops.window.pre_visibility(type, event, _appcore_mw_context.data);

	if (ev->type == ECORE_WL2_WINDOW_VISIBILITY_TYPE_PRE_UNOBSCURED)
		__remove_flush_timer();

	return ECORE_CALLBACK_RENEW;
}

EXPORT_API int appcore_multiwindow_base_init(appcore_multiwindow_base_ops ops, int argc, char **argv, void *data)
{
	_appcore_mw_context.ops = ops;
	_appcore_mw_context.data = data;
	_appcore_mw_context.argc = argc;
	_appcore_mw_context.argv = argv;

	return appcore_base_init(ops.base, argc, argv, data);
}

static void __destroy_iter(gpointer data, gpointer user_data)
{
	appcore_multiwindow_base_instance *inst = data;

	if (!inst)
		return;

	appcore_multiwindow_base_instance_exit(inst);
}

static void __destroy_all(void)
{
	g_list_foreach(_appcore_mw_context.instances, __destroy_iter, NULL);
}

static void __free_class(gpointer data)
{
	appcore_multiwindow_base_class *cls = data;

	free(cls->id);
	free(cls);
}

EXPORT_API void appcore_multiwindow_base_fini(void)
{
	__destroy_all();
	g_list_free_full(_appcore_mw_context.classes, __free_class);
	_appcore_mw_context.classes = NULL;

	if (_appcore_mw_context.hshow) {
		ecore_event_handler_del(_appcore_mw_context.hshow);
		_appcore_mw_context.hshow = NULL;
	}

	if (_appcore_mw_context.hhide) {
		ecore_event_handler_del(_appcore_mw_context.hhide);
		_appcore_mw_context.hhide = NULL;
	}

	if (_appcore_mw_context.hvchange) {
		ecore_event_handler_del(_appcore_mw_context.hvchange);
		_appcore_mw_context.hvchange = NULL;
	}

	if (_appcore_mw_context.hlower) {
		ecore_event_handler_del(_appcore_mw_context.hlower);
		_appcore_mw_context.hlower = NULL;
	}

	if (_appcore_mw_context.hpvchange) {
		ecore_event_handler_del(_appcore_mw_context.hpvchange);
		_appcore_mw_context.hpvchange = NULL;
	}

	appcore_base_fini();
}

EXPORT_API void appcore_multiwindow_base_exit(void)
{
	if (_appcore_mw_context.ops.base.exit)
		_appcore_mw_context.ops.base.exit(_appcore_mw_context.data);
}

static int __on_receive(aul_type type, bundle *b, void *data)
{
	return appcore_multiwindow_base_on_receive(type, b);
}

static int __on_create(void *data)
{
	return appcore_multiwindow_base_on_create();
}

static int __on_terminate(void *data)
{
	return appcore_multiwindow_base_on_terminate();
}

static void __on_trim_memory(void *data)
{
	appcore_multiwindow_base_on_trim_memory();
}

static void __window_on_show(int type, void *event, void *data)
{
	appcore_multiwindow_base_window_on_show(type, event);
}

static void __window_on_hide(int type, void *event, void *data)
{
	appcore_multiwindow_base_window_on_hide(type, event);
}

static void __window_on_lower(int type, void *event, void *data)
{
	appcore_multiwindow_base_window_on_lower(type, event);
}

static void __window_on_visibility(int type, void *event, void *data)
{
	appcore_multiwindow_base_window_on_visibility(type, event);
}

static void __window_on_pre_visibility(int type, void *event, void *data)
{
	appcore_multiwindow_base_window_on_pre_visibility(type, event);
}

EXPORT_API appcore_multiwindow_base_ops appcore_multiwindow_base_get_default_ops(void)
{
	appcore_multiwindow_base_ops ops;

	ops.base = appcore_base_get_default_ops();

	/* override methods */
	ops.base.create = __on_create;
	ops.base.terminate = __on_terminate;
	ops.base.receive = __on_receive;
	ops.base.init = NULL;
	ops.base.finish = NULL;
	ops.base.run = NULL;
	ops.base.exit = NULL;
	ops.base.trim_memory = __on_trim_memory;

	ops.window.show = __window_on_show;
	ops.window.hide = __window_on_hide;
	ops.window.lower = __window_on_lower;
	ops.window.visibility = __window_on_visibility;
	ops.window.pre_visibility = __window_on_pre_visibility;

	return ops;
}

EXPORT_API int appcore_multiwindow_base_on_receive(aul_type type, bundle *b)
{
	appcore_base_on_receive(type, b);

	return 0;
}

EXPORT_API int appcore_multiwindow_base_on_create(void)
{
	appcore_base_on_create();

	_appcore_mw_context.hshow = ecore_event_handler_add(ECORE_WL2_EVENT_WINDOW_SHOW, __stub_show_cb, NULL);
	_appcore_mw_context.hhide = ecore_event_handler_add(ECORE_WL2_EVENT_WINDOW_HIDE, __stub_hide_cb, NULL);
	_appcore_mw_context.hvchange = ecore_event_handler_add(ECORE_WL2_EVENT_WINDOW_VISIBILITY_CHANGE,
			__stub_visibility_cb, NULL);
	_appcore_mw_context.hlower = ecore_event_handler_add(ECORE_WL2_EVENT_WINDOW_LOWER, __stub_lower_cb, NULL);
	_appcore_mw_context.hpvchange = ecore_event_handler_add(ECORE_WL2_EVENT_WINDOW_PRE_VISIBILITY_CHANGE,
			__stub_pre_visibility_cb, NULL);

	return 0;
}

EXPORT_API int appcore_multiwindow_base_on_terminate(void)
{
	appcore_base_on_terminate();

	return 0;
}

EXPORT_API int appcore_multiwindow_base_on_control(bundle *b)
{
	appcore_base_on_control(b);

	return 0;
}

EXPORT_API int appcore_multiwindow_base_on_trim_memory(void)
{
	return appcore_base_on_trim_memory();
}
