/*
 * Copyright (c) 2011 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlog.h>

#include <app_common_internal.h>
#include <app_internal.h>
#include <tizen_error.h>

#include <app.h>
#include "app_extension.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "CAPI_APPFW_APPLICATION"

typedef struct {
	app_event_callback_s *callback;
	void *data;
} app_context_s;

static bool __on_create(void *data)
{
	app_context_s *context = data;

	if (context->callback->create)
		return context->callback->create(context->data);

	return false;
}

static void __on_terminate(void *data)
{
	app_context_s *context = data;

	if (context->callback->terminate)
		context->callback->terminate(context->data);
}

/* LCOV_EXCL_START */
static void __on_pause(void *data)
{
	app_context_s *context = data;

	if (context->callback->pause)
		context->callback->pause(context->data);
}
/* LCOV_EXCL_STOP */

/* LCOV_EXCL_START */
static void __on_resume(void *data)
{
	app_context_s *context = data;

	if (context->callback->resume)
		context->callback->resume(context->data);

}
/* LCOV_EXCL_STOP */

static void __on_app_control(app_control_h app_control, void *data)
{
	app_context_s *context = data;

	if (context->callback->app_control)
		context->callback->app_control(app_control, context->data);
}

static void __on_low_memory(app_event_info_h event_info, void *data)
{
	app_context_s *context = data;

	if (context->callback->low_memory)
		context->callback->low_memory(context->data);
}

static void __on_low_battery(app_event_info_h event_info, void *data)
{
	app_context_s *context = data;

	if (context->callback->low_battery)
		context->callback->low_battery(context->data);
}

/* LCOV_EXCL_START */
static void __on_rotation_event(app_event_info_h event_info, void *data)
{
	app_context_s *context = data;

	if (context->callback->device_orientation) {
		app_device_orientation_e ori;
		app_event_get_device_orientation(event_info, &ori);
		context->callback->device_orientation(ori, context->data);
	}

}
/* LCOV_EXCL_STOP */

static void __on_lang_changed(app_event_info_h event_info, void *data)
{
	app_context_s *context = data;

	if (context->callback->language_changed)
		context->callback->language_changed(context->data);
}

static void __on_region_changed(app_event_info_h event_info, void *data)
{
	app_context_s *context = data;

	if (context->callback->region_format_changed)
		context->callback->region_format_changed(context->data);
}

int app_main(int argc, char **argv, app_event_callback_s *callback, void *data)
{
	ui_app_lifecycle_callback_s cb = {
		.create = __on_create,
		.terminate = __on_terminate,
		.pause = __on_pause,
		.resume = __on_resume,
		.app_control = __on_app_control
	};

	app_context_s app_context = {
		.callback = callback,
		.data = data
	};

	app_event_handler_h handler;

	if (!callback)
		return app_error(APP_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (callback->low_memory)
		ui_app_add_event_handler(&handler, APP_EVENT_LOW_MEMORY, __on_low_memory, &app_context);
	if (callback->low_battery)
		ui_app_add_event_handler(&handler, APP_EVENT_LOW_BATTERY, __on_low_battery, &app_context);
	if (callback->language_changed)
		ui_app_add_event_handler(&handler, APP_EVENT_LANGUAGE_CHANGED, __on_lang_changed, &app_context);
	if (callback->device_orientation)
		ui_app_add_event_handler(&handler, APP_EVENT_DEVICE_ORIENTATION_CHANGED, __on_rotation_event, &app_context);
	if (callback->region_format_changed)
		ui_app_add_event_handler(&handler, APP_EVENT_REGION_FORMAT_CHANGED, __on_region_changed, &app_context);

	return ui_app_main(argc, argv, &cb, &app_context);
}

int app_efl_main(int *argc, char ***argv, app_event_callback_s *callback, void *user_data)
{
	if (argc == NULL || argv == NULL)
		return app_error(APP_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	return app_main(*argc, *argv, callback, user_data);
}

void app_exit(void)
{
	ui_app_exit();
}

void app_efl_exit(void)
{
	ui_app_exit();
}



