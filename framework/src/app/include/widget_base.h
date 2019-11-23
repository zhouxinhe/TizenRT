/*
 * Copyright (c) 2015 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
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

#pragma once

#include <stdbool.h>
#include <libintl.h>
#include <bundle.h>
#include <aul.h>
#include <app_common.h>
#include <appcore_multiwindow_base.h>

#define FEATURE_SHELL_APPWIDGET "http://tizen.org/feature/shell.appwidget"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum widget_base_destroy_type {
	WIDGET_BASE_DESTROY_TYPE_PERMANENT = 0x00,
	WIDGET_BASE_DESTROY_TYPE_TEMPORARY = 0x01,
} widget_base_destroy_type_e;

typedef enum widget_base_error {
	WIDGET_BASE_ERROR_NONE = TIZEN_ERROR_NONE, /**< Operation is successfully completed */
	WIDGET_BASE_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER, /**< Invalid function parameter */
	WIDGET_BASE_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY, /**< Out of memory */
	WIDGET_BASE_ERROR_RESOURCE_BUSY = TIZEN_ERROR_RESOURCE_BUSY, /**< Device or resource busy */
	WIDGET_BASE_ERROR_PERMISSION_DENIED = TIZEN_ERROR_PERMISSION_DENIED, /**< Permission denied */
	WIDGET_BASE_ERROR_CANCELED = TIZEN_ERROR_CANCELED, /**< Operation Canceled */
	WIDGET_BASE_ERROR_IO_ERROR = TIZEN_ERROR_IO_ERROR, /**< I/O error */
	WIDGET_BASE_ERROR_TIMED_OUT = TIZEN_ERROR_TIMED_OUT, /**< Time out */
	WIDGET_BASE_ERROR_NOT_SUPPORTED = TIZEN_ERROR_NOT_SUPPORTED, /**< Not supported */
	WIDGET_BASE_ERROR_FILE_NO_SPACE_ON_DEVICE = TIZEN_ERROR_FILE_NO_SPACE_ON_DEVICE, /**< No space left on device */
	WIDGET_BASE_ERROR_FAULT = TIZEN_ERROR_WIDGET | 0x0001, /**< Fault - Unable to recover from the error */
	WIDGET_BASE_ERROR_ALREADY_EXIST = TIZEN_ERROR_WIDGET | 0x0002, /**< Already exists */
	WIDGET_BASE_ERROR_ALREADY_STARTED = TIZEN_ERROR_WIDGET | 0x0004, /**< Operation is already started */
	WIDGET_BASE_ERROR_NOT_EXIST = TIZEN_ERROR_WIDGET | 0x0008, /**< Not exists */
	WIDGET_BASE_ERROR_DISABLED = TIZEN_ERROR_WIDGET | 0x0010, /**< Disabled */
	WIDGET_BASE_ERROR_MAX_EXCEEDED = TIZEN_ERROR_WIDGET | 0x0011, /**< Maximum number of instances exceeded (Since 3.0) */
} widget_base_error_e;

typedef appcore_multiwindow_base_instance_h widget_base_instance_h;

typedef struct _widget_base_class_ops {
	int (*create)(widget_base_instance_h instance_h, bundle *content,
			int w, int h, void *class_data);
	int (*destroy)(widget_base_instance_h instance_h,
			widget_base_destroy_type_e reason, bundle *content,
			void *class_data);
	int (*pause)(widget_base_instance_h instance_h, void *class_data);
	int (*resume)(widget_base_instance_h instance_h, void *class_data);
	int (*resize)(widget_base_instance_h instance_h, int w, int h, void *class_data);
	int (*update)(widget_base_instance_h instance_h, bundle *content, int force,
			void *class_data);
} widget_base_class_ops;

typedef struct _widget_base_ops {
	int (*create)(void *data);
	int (*terminate)(void *data);
	void (*init)(int argc, char **argv, void *data);
	void (*finish)(void);
	void (*run)(void *data);
	void (*exit)(void *data);
	void (*trim_memory)(void *data);
} widget_base_ops;

typedef struct _widget_base_class {
	char *id;
	widget_base_class_ops ops;
} widget_base_class;

typedef bool (*widget_base_instance_cb)(widget_base_instance_h instance, void *data);

int widget_base_foreach_context(widget_base_instance_cb cb, void *data);
int widget_base_terminate_context(widget_base_instance_h instance_h);
int widget_base_add_event_handler(app_event_handler_h *event_handler,
					app_event_type_e event_type,
					app_event_cb callback,
					void *user_data);
int widget_base_remove_event_handler(app_event_handler_h
						event_handler);
int widget_base_context_set_content_info(widget_base_instance_h instance_h,
		bundle *content_info);
int widget_base_context_get_tag(widget_base_instance_h instance_h, void **tag);
int widget_base_context_set_tag(widget_base_instance_h instance_h, void *tag);
void *widget_base_context_get_user_data(widget_base_instance_h instance_h);
int widget_base_context_set_user_data(widget_base_instance_h instance_h,
		void *user_data);
int widget_base_context_get_id(widget_base_instance_h instance_h, char **id);
const char *widget_base_get_viewer_endpoint(void);
int widget_base_init(widget_base_ops ops, int argc, char **argv, void *data);
int widget_base_on_create(void);
int widget_base_on_terminate(void);
int widget_base_on_init(int argc, char **argv);
void widget_base_on_finish(void);
void widget_base_on_run(void);
void widget_base_on_exit(void);
int widget_base_on_trim_memory(void);
widget_base_ops widget_base_get_default_ops(void);
void widget_base_fini(void);
int widget_base_exit(void);
int widget_base_context_window_bind(
		widget_base_instance_h instance_h, const char *id,
		Ecore_Wl2_Window *wl_win);
int widget_base_class_on_create(widget_base_instance_h instance_h,
		bundle *content, int w, int h);
int widget_base_class_on_pause(widget_base_instance_h instance_h);
int widget_base_class_on_resume(widget_base_instance_h instance_h);
int widget_base_class_on_resize(widget_base_instance_h instance_h,
		int w, int h);
int widget_base_class_on_update(widget_base_instance_h instance_h,
		bundle *content, int force);
int widget_base_class_on_destroy(widget_base_instance_h instance_h,
		widget_base_destroy_type_e reason, bundle *content);
widget_base_class widget_base_class_get_default(void);
widget_base_class *widget_base_class_add(widget_base_class cls,
		const char *class_id, void *class_data);

#ifdef __cplusplus
}
#endif
