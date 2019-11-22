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

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <stdbool.h>

#include <Ecore_Wl2.h>
#include <glib-object.h>
#include <glib.h>
#include <gio/gio.h>

#include "appcore_base.h"
#include "appcore_multiwindow_base.h"
#include "appcore_multiwindow_base_private.h"

typedef struct _win_context {
	appcore_multiwindow_base_instance_h inst;
	int win_id;
} win_context;

static GList *__win_contexts;

static int __comp(gconstpointer a, gconstpointer b)
{
	const win_context *cxt = a;

	if (!a || !b)
		return -1;

	if (cxt->inst == b)
		return 0;

	return -1;
}

static int __comp_wid(gconstpointer a, gconstpointer b)
{
	int wid = GPOINTER_TO_INT(b);
	const win_context *cxt = a;

	if (!a || !b)
		return -1;

	if (cxt->win_id == wid)
		return 0;

	return -1;
}

static win_context *__find_win_context(appcore_multiwindow_base_instance_h h)
{
	GList *node = g_list_find_custom(__win_contexts, h, __comp);

	if (!node)
		return NULL;

	return node->data;
}

static win_context *__find_win_context_by_wid(int wid)
{
	GList *node = g_list_find_custom(__win_contexts, GINT_TO_POINTER(wid), __comp_wid);

	if (!node)
		return NULL;

	return node->data;
}

EXPORT_API bool appcore_multiwindow_base_window_is_resumed(void)
{
	win_context *ctx;
	GList *iter;

	iter = __win_contexts;
	while (iter) {
		ctx = (win_context *)iter->data;
		if (appcore_multiwindow_base_instance_is_resumed(ctx->inst))
			return true;
		iter = g_list_next(iter);
	}

	return false;
}

EXPORT_API void appcore_multiwindow_base_window_on_show(int type, void *event)
{
}

EXPORT_API void appcore_multiwindow_base_window_on_hide(int type, void *event)
{
	Ecore_Wl2_Event_Window_Hide *ev = event;
	win_context *cxt = __find_win_context_by_wid(ev->win);

	if (!cxt)
		return;

	__win_contexts = g_list_remove(__win_contexts, cxt);
	free(cxt);
}

EXPORT_API void appcore_multiwindow_base_window_on_lower(int type, void *event)
{
}

EXPORT_API void appcore_multiwindow_base_window_on_visibility(int type, void *event)
{
	Ecore_Wl2_Event_Window_Visibility_Change *ev = event;
	win_context *cxt = __find_win_context_by_wid(ev->win);

	if (!cxt)
		return;

	if (ev->fully_obscured)
		appcore_multiwindow_base_instance_pause(cxt->inst);
	else
		appcore_multiwindow_base_instance_resume(cxt->inst);
}

EXPORT_API void appcore_multiwindow_base_window_on_pre_visibility(int type, void *event)
{
	Ecore_Wl2_Event_Window_Pre_Visibility_Change *ev = event;
	win_context *cxt = __find_win_context_by_wid(ev->win);

	if (!cxt)
		return;

	if (ev->type == ECORE_WL2_WINDOW_VISIBILITY_TYPE_PRE_UNOBSCURED)
		appcore_multiwindow_base_instance_resume(cxt->inst);
}

EXPORT_API void appcore_multiwindow_base_window_bind(appcore_multiwindow_base_instance_h h, Ecore_Wl2_Window *wl_win)
{
	win_context *cxt;
	int id;

	if (!wl_win) {
		_ERR("Invalid parameter");
		return;
	}

	cxt = __find_win_context(h);
	if (cxt) {
		_ERR("This instance is already binded");
		return;
	}

	id = ecore_wl2_window_id_get(wl_win);

	cxt = malloc(sizeof(win_context));
	if (cxt == NULL) {
		_ERR("Out of memory");
		return;
	}

	cxt->win_id = id;
	cxt->inst = h;
	__win_contexts = g_list_append(__win_contexts, cxt);
}

EXPORT_API void appcore_multiwindow_base_window_unbind(appcore_multiwindow_base_instance_h h)
{
	win_context *cxt;

	cxt = __find_win_context(h);
	if (!cxt)
		return;

	__win_contexts = g_list_remove(__win_contexts, cxt);
	free(cxt);
}

