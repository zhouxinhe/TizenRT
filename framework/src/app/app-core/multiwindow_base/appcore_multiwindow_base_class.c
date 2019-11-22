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

#include <glib-object.h>
#include <glib.h>
#include <gio/gio.h>

#include "appcore_base.h"
#include "appcore_multiwindow_base.h"
#include "appcore_multiwindow_base_private.h"

extern appcore_multiwindow_base_context _appcore_mw_context;

static void __on_create(appcore_multiwindow_base_instance_h context, void *data)
{
	appcore_multiwindow_base_class_on_create(context);
}

static void __on_terminate(appcore_multiwindow_base_instance_h context, void *data)
{
	appcore_multiwindow_base_class_on_terminate(context);
}

static void __on_pause(appcore_multiwindow_base_instance_h context, void *data)
{
	appcore_multiwindow_base_class_on_pause(context);
}

static void __on_resume(appcore_multiwindow_base_instance_h context, void *data)
{
	appcore_multiwindow_base_class_on_resume(context);
}

EXPORT_API appcore_multiwindow_base_class appcore_multiwindow_base_class_get_default(void)
{
	appcore_multiwindow_base_class cls = { 0, };

	cls.create = __on_create;
	cls.terminate = __on_terminate;
	cls.pause = __on_pause;
	cls.resume = __on_resume;

	return cls;
}

EXPORT_API void appcore_multiwindow_base_class_add(appcore_multiwindow_base_class cls)
{
	appcore_multiwindow_base_class *c;

	if (!cls.id)
		return;

	c = malloc(sizeof(appcore_multiwindow_base_class));

	if (!c)
		return;

	*c = cls;
	c->id = strdup(cls.id);
	_appcore_mw_context.classes = g_list_append(_appcore_mw_context.classes, c);
}

EXPORT_API void appcore_multiwindow_base_class_on_create(appcore_multiwindow_base_instance_h context)
{
}

EXPORT_API void appcore_multiwindow_base_class_on_terminate(appcore_multiwindow_base_instance_h context)
{
	appcore_multiwindow_base_window_unbind(context);
}

EXPORT_API void appcore_multiwindow_base_class_on_pause(appcore_multiwindow_base_instance_h context)
{
}

EXPORT_API void appcore_multiwindow_base_class_on_resume(appcore_multiwindow_base_instance_h context)
{
}


