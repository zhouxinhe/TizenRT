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
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <malloc.h>

#include <glib-object.h>
#include <glib.h>
#include <gio/gio.h>

#include "appcore_base.h"
#include "appcore_multiwindow_base.h"
#include "appcore_multiwindow_base_private.h"

extern appcore_multiwindow_base_context _appcore_mw_context;

static int __comp(gconstpointer a, gconstpointer b)
{
	const appcore_multiwindow_base_class *cls = a;

	return strcmp(cls->id, b);
}

EXPORT_API appcore_multiwindow_base_instance_h appcore_multiwindow_base_instance_run(const char *class_id, const char *id, void *extra)
{
	appcore_multiwindow_base_instance *inst;
	GList * class_node = g_list_find_custom(_appcore_mw_context.classes, class_id, __comp);

	if (!class_node)
		return NULL;

	if (appcore_multiwindow_base_instance_find(id)) {
		_ERR("alread exist");
		return NULL;
	}

	inst = malloc(sizeof(appcore_multiwindow_base_instance));
	if (!inst)
		return NULL;

	inst->shell = class_node->data;
	inst->window_id = 0;
	inst->id = strdup(id);
	inst->extra = extra;
	inst->is_resumed = false;

	_appcore_mw_context.instances = g_list_append(_appcore_mw_context.instances, inst);
	if (inst->shell->create)
		inst->shell->create(inst, inst->shell->data);

	return inst;
}

EXPORT_API void appcore_multiwindow_base_instance_exit(appcore_multiwindow_base_instance_h context)
{
	appcore_multiwindow_base_instance *inst = context;

	appcore_multiwindow_base_instance_pause(inst);
	if (inst->shell->terminate)
		inst->shell->terminate(inst, inst->shell->data);

	_appcore_mw_context.instances = g_list_remove(_appcore_mw_context.instances, inst);
	free(inst->id);
	free(inst);
}

EXPORT_API void appcore_multiwindow_base_instance_drop(appcore_multiwindow_base_instance_h context)
{
	appcore_multiwindow_base_instance *inst = context;

	inst->shell->terminate(inst, inst->shell->data);

	_appcore_mw_context.instances = g_list_remove(_appcore_mw_context.instances, inst);
	free(inst->id);
	free(inst);
}

EXPORT_API void *appcore_multiwindow_base_instance_get_extra(appcore_multiwindow_base_instance_h context)
{
	appcore_multiwindow_base_instance *inst = context;

	return inst->extra;
}

EXPORT_API void appcore_multiwindow_base_instance_set_extra(appcore_multiwindow_base_instance_h context, void *extra)
{
	appcore_multiwindow_base_instance *inst = context;

	inst->extra = extra;
}

EXPORT_API bool appcore_multiwindow_base_instance_is_resumed(appcore_multiwindow_base_instance_h context)
{
	appcore_multiwindow_base_instance *inst = context;

	return inst->is_resumed;
}

EXPORT_API void appcore_multiwindow_base_instance_pause(appcore_multiwindow_base_instance_h context)
{
	appcore_multiwindow_base_instance *inst = context;

	if (!inst->is_resumed)
		return;

	if (inst->shell->pause)
		inst->shell->pause(inst, inst->shell->data);
	inst->is_resumed = false;
}

EXPORT_API void appcore_multiwindow_base_instance_resume(appcore_multiwindow_base_instance_h context)
{
	appcore_multiwindow_base_instance *inst = context;

	if (inst->is_resumed)
		return;

	if (inst->shell->resume)
		inst->shell->resume(inst, inst->shell->data);
	inst->is_resumed = true;
}

EXPORT_API const char *appcore_multiwindow_base_instance_get_id(appcore_multiwindow_base_instance_h context)
{
	appcore_multiwindow_base_instance *inst = context;

	return inst->id;
}

EXPORT_API const char *appcore_multiwindow_base_instance_get_class_id(appcore_multiwindow_base_instance_h context)
{
	appcore_multiwindow_base_instance *inst = context;

	return inst->shell->id;
}

EXPORT_API const appcore_multiwindow_base_class *appcore_multiwindow_base_instance_get_class(appcore_multiwindow_base_instance_h context)
{
	appcore_multiwindow_base_instance *inst = context;

	return inst->shell;
}

static int __comp_id(gconstpointer a, gconstpointer b)
{
	const appcore_multiwindow_base_instance *inst = a;

	return strcmp(inst->id, b);
}

EXPORT_API appcore_multiwindow_base_instance_h appcore_multiwindow_base_instance_find(const char *id)
{
	GList * inst_node = g_list_find_custom(_appcore_mw_context.instances, id, __comp_id);

	if (!inst_node)
		return NULL;

	return inst_node->data;
}

EXPORT_API void appcore_multiwindow_base_instance_foreach(const char *class_id,
		appcore_multiwindow_base_instance_cb cb, void *data)
{
	GList * inst_node = _appcore_mw_context.instances;
	appcore_multiwindow_base_instance *inst;

	if (!class_id || !cb)
		return;

	while (inst_node) {
		inst = inst_node->data;

		if (!strcmp(class_id, inst->shell->id))
			cb(class_id, inst->id, inst, data);

		inst_node = g_list_next(inst_node);
	}
}

EXPORT_API void appcore_multiwindow_base_instance_foreach_full(appcore_multiwindow_base_instance_cb cb,
		void *data)
{
	GList * inst_node = _appcore_mw_context.instances;
	appcore_multiwindow_base_instance *inst;

	if (!cb)
		return;

	while (inst_node) {
		inst = inst_node->data;
		cb(inst->shell->id, inst->id, inst, data);
		inst_node = g_list_next(inst_node);
	}
}

EXPORT_API int appcore_multiwindow_base_instance_get_cnt(void)
{
	return g_list_length(_appcore_mw_context.instances);
}


