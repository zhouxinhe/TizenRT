/*
 * Copyright (c) 2000 - 2017 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "appcore-internal.h"
#include "appcore-efl.h"
#include "appcore_efl_base.h"

struct appcore_efl_context {
	struct appcore_ops ops;
};

static struct appcore_efl_context __context;

static int __ui_app_create(void *data)
{
	appcore_efl_base_on_create();

	if (__context.ops.create) {
		if (__context.ops.create(__context.ops.data) < 0)
			return -1;
	}

	return 0;
}

static int __ui_app_terminate(void *data)
{
	appcore_efl_base_on_terminate();

	if (__context.ops.terminate)
		__context.ops.terminate(__context.ops.data);

	return 0;
}

static int __ui_app_control(bundle *b, void *data)
{
	appcore_efl_base_on_control(b);

	if (__context.ops.reset)
		__context.ops.reset(b, __context.ops.data);

	return 0;
}

static int __ui_app_pause(void *data)
{
	appcore_efl_base_on_pause();

	if (__context.ops.pause)
		__context.ops.pause(__context.ops.data);
	return 0;
}

static int __ui_app_resume(void *data)
{
	appcore_efl_base_on_resume();

	if (__context.ops.resume)
		__context.ops.resume(__context.ops.data);
	return 0;
}

EXPORT_API int appcore_efl_init(const char *name, int *argc, char ***argv,
		     struct appcore_ops *ops)
{
	int ret;
	appcore_efl_base_ops efl_ops = appcore_efl_base_get_default_ops();

	/* override methods */
	efl_ops.ui_base.base.create = __ui_app_create;
	efl_ops.ui_base.base.control = __ui_app_control;
	efl_ops.ui_base.base.terminate = __ui_app_terminate;
	efl_ops.ui_base.pause = __ui_app_pause;
	efl_ops.ui_base.resume = __ui_app_resume;

	__context.ops = *ops;

	ret = appcore_efl_base_init(efl_ops, *argc, *argv, NULL,
			APPCORE_EFL_BASE_HINT_WINDOW_GROUP_CONTROL |
			APPCORE_EFL_BASE_HINT_WINDOW_STACK_CONTROL |
			APPCORE_EFL_BASE_HINT_BG_LAUNCH_CONTROL |
			APPCORE_EFL_BASE_HINT_HW_ACC_CONTROL |
			APPCORE_EFL_BASE_HINT_WINDOW_AUTO_CONTROL |
			APPCORE_EFL_BASE_HINT_LEGACY_CONTROL);

	return ret;
}

EXPORT_API void appcore_efl_fini(void)
{
	appcore_efl_base_fini();
}

EXPORT_API int appcore_efl_main(const char *name, int *argc, char ***argv,
				struct appcore_ops *ops)
{
	int r;

	r = appcore_efl_init(name, argc, argv, ops);
	if (r < 0)
		return r;

	appcore_efl_fini();

	return 0;
}

EXPORT_API void appcore_group_attach()
{
	appcore_efl_base_group_add();
}

EXPORT_API void appcore_group_lower()
{
	appcore_efl_base_group_remove();
}

EXPORT_API unsigned int appcore_get_main_window(void)
{
	return appcore_efl_base_get_main_window();
}

EXPORT_API unsigned int appcore_get_main_surface(void)
{
	return appcore_get_main_surface();
}

EXPORT_API int appcore_set_system_resource_reclaiming(bool enable)
{
	appcore_efl_base_set_system_resource_reclaiming(enable);
	return 0;
}
