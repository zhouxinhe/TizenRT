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

#pragma once

#include <libintl.h>
#include <bundle.h>
#include <aul.h>
#include <appcore_base.h>
#include <Ecore_Wl2.h>

typedef struct _appcore_multiwindow_base_window_ops {
	void (*show)(int type, void *event, void *data);
	void (*hide)(int type, void *event, void *data);
	void (*lower)(int type, void *event, void *data);
	void (*visibility)(int type, void *event, void *data);
	void (*pre_visibility)(int type, void *event, void *data);
} appcore_multiwindow_base_window_ops;

typedef struct _appcore_multiwindow_base_ops {
	appcore_base_ops base;
	appcore_multiwindow_base_window_ops window;
} appcore_multiwindow_base_ops;

typedef void *appcore_multiwindow_base_instance_h;

typedef struct _appcore_multiwindow_base_class {
	char *id;
	void *data;
	void (*create)(appcore_multiwindow_base_instance_h context, void *data);
	void (*terminate)(appcore_multiwindow_base_instance_h context, void *data);
	void (*pause)(appcore_multiwindow_base_instance_h context, void *data);
	void (*resume)(appcore_multiwindow_base_instance_h context, void *data);
} appcore_multiwindow_base_class;

typedef void (*appcore_multiwindow_base_instance_cb)(const char *class_id,
	const char *id, appcore_multiwindow_base_instance_h context, void *data);

#ifdef __cplusplus
extern "C" {
#endif

int appcore_multiwindow_base_init(appcore_multiwindow_base_ops ops, int argc, char **argv, void *data);
void appcore_multiwindow_base_fini(void);
void appcore_multiwindow_base_exit(void);
appcore_multiwindow_base_ops appcore_multiwindow_base_get_default_ops(void);
int appcore_multiwindow_base_on_receive(aul_type type, bundle *b);
int appcore_multiwindow_base_on_create(void);
int appcore_multiwindow_base_on_terminate(void);
int appcore_multiwindow_base_on_control(bundle *b);
int appcore_multiwindow_base_on_trim_memory(void);
void appcore_multiwindow_base_window_on_show(int type, void *event);
void appcore_multiwindow_base_window_on_hide(int type, void *event);
void appcore_multiwindow_base_window_on_lower(int type, void *event);
void appcore_multiwindow_base_window_on_visibility(int type, void *event);
void appcore_multiwindow_base_window_on_pre_visibility(int type, void *event);
void appcore_multiwindow_base_window_bind(appcore_multiwindow_base_instance_h h, Ecore_Wl2_Window *wl_win);
void appcore_multiwindow_base_window_unbind(appcore_multiwindow_base_instance_h h);
bool appcore_multiwindow_base_window_is_resumed(void);

appcore_multiwindow_base_class appcore_multiwindow_base_class_get_default(void);
void appcore_multiwindow_base_class_add(appcore_multiwindow_base_class cls);
void appcore_multiwindow_base_class_on_create(appcore_multiwindow_base_instance_h context);
void appcore_multiwindow_base_class_on_terminate(appcore_multiwindow_base_instance_h context);
void appcore_multiwindow_base_class_on_pause(appcore_multiwindow_base_instance_h context);
void appcore_multiwindow_base_class_on_resume(appcore_multiwindow_base_instance_h context);

appcore_multiwindow_base_instance_h appcore_multiwindow_base_instance_run(const char *class_id, const char *id, void *extra);
void appcore_multiwindow_base_instance_exit(appcore_multiwindow_base_instance_h context);
void appcore_multiwindow_base_instance_drop(appcore_multiwindow_base_instance_h context);
void *appcore_multiwindow_base_instance_get_extra(appcore_multiwindow_base_instance_h context);
void appcore_multiwindow_base_instance_set_extra(appcore_multiwindow_base_instance_h context, void *extra);
bool appcore_multiwindow_base_instance_is_resumed(appcore_multiwindow_base_instance_h context);
void appcore_multiwindow_base_instance_pause(appcore_multiwindow_base_instance_h context);
void appcore_multiwindow_base_instance_resume(appcore_multiwindow_base_instance_h context);
const char *appcore_multiwindow_base_instance_get_id(appcore_multiwindow_base_instance_h context);
const char *appcore_multiwindow_base_instance_get_class_id(appcore_multiwindow_base_instance_h context);
const appcore_multiwindow_base_class *appcore_multiwindow_base_instance_get_class(appcore_multiwindow_base_instance_h context);
appcore_multiwindow_base_instance_h appcore_multiwindow_base_instance_find(const char *id);
void appcore_multiwindow_base_instance_foreach(const char *class_id, appcore_multiwindow_base_instance_cb cb, void *data);
void appcore_multiwindow_base_instance_foreach_full(appcore_multiwindow_base_instance_cb cb, void *data);
int appcore_multiwindow_base_instance_get_cnt(void);

#ifdef __cplusplus
}
#endif


