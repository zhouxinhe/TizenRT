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


#include <stdlib.h>
#include <glib.h>

#include <bundle.h>
#include <aul.h>
#include <aul_widget.h>
#include <dlog.h>
#include <Elementary.h>
#include <widget_errno.h>
#include <widget_instance.h>

#include "widget_base.h"
#include "widget_app.h"
#include "widget-log.h"
#include "widget-private.h"
#include "widget_app_internal.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "CAPI_WIDGET_APPLICATION"
#define ICONIFY_TIMEOUT 500

struct instance_data {
	Evas_Object *win;
	guint iconify_timer;
	bool is_iconified;
};

struct app_cb_info {
	widget_app_lifecycle_callback_s *callback;
	void *user_data;
};

struct app_class_cb_info {
	widget_instance_lifecycle_callback_s callback;
	void *user_data;
};

static GList *__class_data_list;

static int __class_resize(widget_base_instance_h instance_h, int w, int h,
		void *class_data)
{
	int ret = 0;
	struct instance_data *data;
	struct app_class_cb_info *callback_data =
			(struct app_class_cb_info *)class_data;

	widget_base_class_on_resize(instance_h, w, h);
	data = (struct instance_data *)
			widget_base_context_get_user_data(instance_h);

	if (!data) {
		_E("widget_base_context_get_user_data() returns null");

		return -1;
	}

	if (data->win)
		evas_object_resize(data->win, w, h);
	else
		_E("unable to find window");

	if (callback_data && callback_data->callback.resize) {
		ret = callback_data->callback.resize(
				(widget_context_h)instance_h,
				w, h, callback_data->user_data);
	}

	return ret;
}

static int __class_update(widget_base_instance_h instance_h, bundle *content,
		int force, void *class_data)
{
	int ret = 0;
	struct app_class_cb_info *callback_data =
			(struct app_class_cb_info *)class_data;

	widget_base_class_on_update(instance_h, content, force);
	if (callback_data && callback_data->callback.update) {
		ret = callback_data->callback.update(
				(widget_context_h)instance_h,
				content, force, callback_data->user_data);
	}

	return ret;
}

static int __class_create(widget_base_instance_h instance_h, bundle *content,
		int w, int h, void *class_data)
{
	int ret = -1;
	struct app_class_cb_info *callback_data =
			(struct app_class_cb_info *)class_data;

	widget_base_class_on_create(instance_h, content, w, h);
	if (callback_data && callback_data->callback.create) {
		ret = callback_data->callback.create(
				(widget_context_h)instance_h,
				content, w, h, callback_data->user_data);
		aul_widget_write_log(LOG_TAG, "[%s:%d]  ret : %d",
			__FUNCTION__, __LINE__, ret);
	}
	return ret;
}

static int __class_destroy(widget_base_instance_h instance_h,
		widget_base_destroy_type_e reason, bundle *content,
		void *class_data)
{
	int ret = 0;
	struct instance_data *data;
	struct app_class_cb_info *callback_data =
			(struct app_class_cb_info *)class_data;

	if (callback_data && callback_data->callback.destroy) {
		ret = callback_data->callback.destroy(
				(widget_context_h)instance_h,
				reason, content, callback_data->user_data);
		aul_widget_write_log(LOG_TAG, "[%s:%d]  ret : %d",
			__FUNCTION__, __LINE__, ret);
	}

	data = (struct instance_data *)widget_base_context_get_user_data(instance_h);
	if (data != NULL) {
		widget_base_context_set_user_data(instance_h, NULL);
		if (data->iconify_timer > 0)
			g_source_remove(data->iconify_timer);
		free(data);
	}

	widget_base_class_on_destroy(instance_h, reason, content);

	return ret;
}

static gboolean __iconify_timeout_cb(gpointer user_data)
{
	struct instance_data *data = user_data;
	Ecore_Wl2_Window *win = ecore_evas_wayland2_window_get(
			ecore_evas_ecore_evas_get(evas_object_evas_get(data->win)));

	if (win) {
		ecore_wl2_window_iconified_set(win, EINA_TRUE);
		data->is_iconified = true;
		_D("set iconify true");
	}

	data->iconify_timer = 0;

	return G_SOURCE_REMOVE;
}

static int __class_pause(widget_base_instance_h instance_h, void *class_data)
{
	int ret = 0;
	struct app_class_cb_info *callback_data =
			(struct app_class_cb_info *)class_data;
	struct instance_data *data = (struct instance_data *)
			widget_base_context_get_user_data(instance_h);

	if (data->iconify_timer > 0)
		g_source_remove(data->iconify_timer);

	data->iconify_timer = g_timeout_add(ICONIFY_TIMEOUT,
			__iconify_timeout_cb, data);

	widget_base_class_on_pause(instance_h);
	if (callback_data && callback_data->callback.pause) {
		ret = callback_data->callback.pause(
				(widget_context_h)instance_h,
				callback_data->user_data);
	}

	return ret;
}

static int __class_resume(widget_base_instance_h instance_h, void *class_data)
{
	int ret = 0;
	struct app_class_cb_info *callback_data =
			(struct app_class_cb_info *)class_data;
	Ecore_Wl2_Window *win;
	struct instance_data *data = (struct instance_data *)
			widget_base_context_get_user_data(instance_h);

	if (data->iconify_timer > 0) {
		g_source_remove(data->iconify_timer);
		data->iconify_timer = 0;
	}

	if (data->is_iconified) {
		win = ecore_evas_wayland2_window_get(
			ecore_evas_ecore_evas_get(evas_object_evas_get(data->win)));
		if (win) {
			ecore_wl2_window_iconified_set(win, EINA_FALSE);
			data->is_iconified = false;
			_D("set iconify false");
		}
	}

	widget_base_class_on_resume(instance_h);
	if (callback_data && callback_data->callback.resume) {
		ret = callback_data->callback.resume(
				(widget_context_h)instance_h,
				callback_data->user_data);
	}

	return ret;
}

static int __widget_app_create(void *data)
{
	struct app_cb_info *cb_info = (struct app_cb_info *)data;
	widget_app_lifecycle_callback_s *callback;

	widget_base_on_create();
	if (cb_info && cb_info->callback && cb_info->callback->create) {
		callback = cb_info->callback;
		if (callback->create(cb_info->user_data) == NULL) {
			_D("fail to create widget");
			return -1;
		}
		_D("widget app is created");
		aul_widget_write_log(LOG_TAG, "[%s:%d]", __FUNCTION__, __LINE__);
		return 0;
	}

	return -1;
}

static int __widget_app_terminate(void *data)
{
	struct app_cb_info *cb_info = (struct app_cb_info *)data;
	widget_app_lifecycle_callback_s *callback;

	if (cb_info && cb_info->callback && cb_info->callback->terminate) {
		callback = cb_info->callback;
		callback->terminate(cb_info->user_data);
		widget_base_on_terminate();
		_D("widget app is terminated");
		aul_widget_write_log(LOG_TAG, "[%s:%d]", __FUNCTION__, __LINE__);
		return 0;
	}

	widget_base_on_terminate();

	return -1;
}

static void __widget_app_init(int argc, char **argv, void *data)
{
	elm_init(argc, argv);
}

static void __widget_app_finish(void)
{
	elm_shutdown();
}

static void __widget_app_run(void *data)
{
	elm_run();
}

static void __widget_app_exit(void *data)
{
	elm_exit();
}

static void __widget_app_trim_memory(void *data)
{
	_D("Trim memory");
	elm_cache_all_flush();
	widget_base_on_trim_memory();
}

EXPORT_API int widget_app_main(int argc, char **argv,
		widget_app_lifecycle_callback_s *callback, void *user_data)
{
	widget_base_ops ops;
	struct app_cb_info cb_info;
	int r;

	if (argc <= 0 || argv == NULL || callback == NULL)
		return widget_app_error(WIDGET_ERROR_INVALID_PARAMETER,
				__FUNCTION__, NULL);

	if (callback->create == NULL)
		return widget_app_error(WIDGET_ERROR_INVALID_PARAMETER,
				__FUNCTION__,
				"widget_app_create_cb() callback must be "
				"registered");

	ops.create = __widget_app_create;
	ops.terminate = __widget_app_terminate;
	ops.init = __widget_app_init;
	ops.finish = __widget_app_finish;
	ops.run = __widget_app_run;
	ops.exit = __widget_app_exit;
	ops.trim_memory = __widget_app_trim_memory;

	cb_info.callback = callback;
	cb_info.user_data = user_data;

	r = widget_base_init(ops, argc, argv, &cb_info);
	widget_base_fini();

	if (__class_data_list) {
		g_list_free_full(__class_data_list, free);
		__class_data_list = NULL;
	}

	return r;
}

EXPORT_API int widget_app_exit(void)
{
	return widget_base_exit();
}

EXPORT_API int widget_app_terminate_context(widget_context_h context)
{
	return widget_base_terminate_context((widget_base_instance_h)context);
}

EXPORT_API int widget_app_foreach_context(widget_context_cb cb, void *data)
{
	return widget_base_foreach_context((widget_base_instance_cb)cb, data);
}

EXPORT_API int widget_app_add_event_handler(app_event_handler_h *event_handler,
					app_event_type_e event_type,
					app_event_cb callback,
					void *user_data)
{
	return widget_base_add_event_handler(event_handler, event_type,
					callback, user_data);
}

EXPORT_API int widget_app_remove_event_handler(app_event_handler_h
						event_handler)
{
	return widget_base_remove_event_handler(event_handler);
}

EXPORT_API const char *widget_app_get_id(widget_context_h context)
{
	int ret;
	char *id;

	if (!context) {
		set_last_result(WIDGET_ERROR_INVALID_PARAMETER);
		return NULL;
	}

	ret = widget_base_context_get_id((widget_base_instance_h)context, &id);
	if (ret != WIDGET_BASE_ERROR_NONE) {
		_E("failed to get context id"); /* LCOV_EXCL_LINE */
		set_last_result(ret); /* LCOV_EXCL_LINE */
		return NULL; /* LCOV_EXCL_LINE */
	}

	set_last_result(WIDGET_ERROR_NONE);
	return id;
}

static void __win_del_cb(void *data, Evas *e, Evas_Object *obj, void *event_info)
{
	char *plug_id;
	plug_id = evas_object_data_del(obj, "___PLUGID");
	free(plug_id);
}

EXPORT_API int widget_app_get_elm_win(widget_context_h context,
					Evas_Object **win)
{
	Evas_Object *ret_win = NULL;
	Ecore_Wl2_Window *wl_win;
	struct instance_data *data;
	char buffer[256];
	int rots[3] = {0};
	int win_id;
	char *id;
	int ret;

	if (context == NULL || win == NULL)
		return widget_app_error(WIDGET_ERROR_INVALID_PARAMETER,
				__FUNCTION__, NULL);

	ret = widget_base_context_get_id((widget_base_instance_h)context, &id);
	if (ret != WIDGET_BASE_ERROR_NONE) {
		_E("failed to get context id"); /* LCOV_EXCL_LINE */
		goto fault; /* LCOV_EXCL_LINE */
	}

	ret_win = elm_win_add(NULL, id, ELM_WIN_BASIC);
	if (ret_win == NULL) {
		_E("failed to create window"); /* LCOV_EXCL_LINE */
		goto fault; /* LCOV_EXCL_LINE */
	}

	elm_win_wm_rotation_preferred_rotation_set(ret_win, -1);
	elm_win_wm_rotation_available_rotations_set(ret_win, rots, 1);

	wl_win = ecore_evas_wayland2_window_get(ecore_evas_ecore_evas_get(evas_object_evas_get(ret_win)));
	if (wl_win == NULL) {
		_E("failed to get wayland window"); /* LCOV_EXCL_LINE */
		goto fault;
	}

	ecore_wl2_window_class_set(wl_win, id);
	elm_win_aux_hint_add(ret_win, "wm.policy.win.user.geometry", "1");
	widget_base_context_window_bind((widget_base_instance_h)context,	id, wl_win);

	/* Set data to use in accessibility */
	snprintf(buffer, sizeof(buffer), "%s:%d", id, getpid());
	evas_object_data_set(ret_win, "___PLUGID", strdup(buffer));
	evas_object_event_callback_add(ret_win, EVAS_CALLBACK_DEL, __win_del_cb, NULL);

	win_id = ecore_wl2_window_id_get(wl_win);
	_D("window created: %d", win_id);

	data = (struct instance_data *)widget_base_context_get_user_data(
			(widget_base_instance_h)context);
	if (data == NULL) {
		data = calloc(1, sizeof(struct instance_data));
		if (data == NULL) {
			_E("failed to alloc instance_data"); /* LCOV_EXCL_LINE */
			goto fault; /* LCOV_EXCL_LINE */
		}

		ret = widget_base_context_set_user_data((widget_base_instance_h)context, data);
		if (ret != WIDGET_BASE_ERROR_NONE) {
			_E("fail to set extra data"); /* LCOV_EXCL_LINE */
			goto fault; /* LCOV_EXCL_LINE */
		}
	}

	data->win = ret_win;
	*win = ret_win;

	return WIDGET_ERROR_NONE;

fault:
	if (ret_win)	/* LCOV_EXCL_LINE */
		evas_object_del(ret_win); /* LCOV_EXCL_LINE */

	return WIDGET_ERROR_FAULT; /* LCOV_EXCL_LINE */
}

EXPORT_API widget_class_h widget_app_class_add(widget_class_h widget_class,
		const char *class_id,
		widget_instance_lifecycle_callback_s callback, void *user_data)
{
	widget_base_class cls;
	struct app_class_cb_info *callback_data;
	widget_class_h wc;

	cls = widget_base_class_get_default();

	/* override methods */
	cls.ops.create = __class_create;
	cls.ops.destroy = __class_destroy;
	cls.ops.pause = __class_pause;
	cls.ops.resume = __class_resume;
	cls.ops.resize = __class_resize;
	cls.ops.update = __class_update;

	callback_data = calloc(1, sizeof(struct app_class_cb_info));
	if (!callback_data) {
		_E("failed to calloc : %s", __FUNCTION__);
		set_last_result(WIDGET_ERROR_OUT_OF_MEMORY);
		return NULL;
	}
	callback_data->callback = callback;
	callback_data->user_data = user_data;

	wc = (widget_class_h)widget_base_class_add(cls, class_id,
			callback_data);

	if (!wc) {
		free(callback_data);
		return NULL;
	}

	__class_data_list = g_list_append(__class_data_list, callback_data);
	set_last_result(WIDGET_ERROR_NONE);

	return wc;
}

EXPORT_API widget_class_h widget_app_class_create(
		widget_instance_lifecycle_callback_s callback, void *user_data)
{
	char *appid;
	widget_class_h wc;

	app_get_id(&appid);
	if (!appid) {
		LOGE("appid is NULL");
		return NULL;
	}

	wc = (widget_class_h)widget_app_class_add(NULL, appid, callback,
			user_data);
	free(appid);

	return wc;
}

EXPORT_API int widget_app_context_set_tag(widget_context_h context, void *tag)
{
	int ret = 0;

	ret = widget_base_context_set_tag((widget_base_instance_h)context, tag);
	if (ret != WIDGET_BASE_ERROR_NONE)
		return widget_app_error(ret, __FUNCTION__, NULL);

	return WIDGET_ERROR_NONE;
}

EXPORT_API int widget_app_context_get_tag(widget_context_h context, void **tag)
{
	int ret = 0;

	ret = widget_base_context_get_tag((widget_base_instance_h)context, tag);
	if (ret != WIDGET_BASE_ERROR_NONE)
		return widget_app_error(ret, __FUNCTION__, NULL);

	return WIDGET_ERROR_NONE;
}

EXPORT_API int widget_app_context_set_content_info(widget_context_h context,
		bundle *content_info)
{
	int ret = 0;

	ret = widget_base_context_set_content_info(
			(widget_base_instance_h)context, content_info);
	if (ret != WIDGET_BASE_ERROR_NONE)
		return widget_app_error(ret, __FUNCTION__, NULL);

	return WIDGET_ERROR_NONE;
}

EXPORT_API int widget_app_context_set_title(widget_context_h context,
		const char *title)
{
	struct instance_data *data = NULL;
	int ret;

	if (!context || !title) {
		_E("Invalid parameter %p %p", context, title);
		return WIDGET_ERROR_INVALID_PARAMETER;
	}

	data = (struct instance_data *)widget_base_context_get_user_data(
			(widget_base_instance_h)context);
	if (data == NULL) {
		data = calloc(1, sizeof(struct instance_data));
		if (data == NULL) {
			return widget_app_error(WIDGET_ERROR_FAULT,
					__FUNCTION__, NULL);
		}
		ret = widget_base_context_set_user_data(context, data);
		if (ret != WIDGET_BASE_ERROR_NONE)
			widget_app_error(ret, __FUNCTION__, NULL);
	}

	if (data->win)
		elm_win_title_set(data->win, title);

	return WIDGET_ERROR_NONE;
}
