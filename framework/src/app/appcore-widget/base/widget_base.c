/*
 * Copyright (c) 2017 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <stdbool.h>

#include <bundle.h>
#include <bundle_internal.h>
#include <aul.h>
#include <aul_widget.h>
#include <dlog.h>
#include <glib.h>
#include <glib-object.h>
#include <stdlib.h>
#include <unistd.h>
#include <widget_errno.h>
#include <widget_instance.h>
#include <aul_app_com.h>
#include <Ecore_Wl2.h>
#include <system_info.h>
#include <vconf.h>
#include <vconf-internal-keys.h>
#include <screen_connector_provider.h>
#include <appcore_multiwindow_base.h>

#include "widget_base.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "CAPI_WIDGET_APPLICATION"
#define APP_TYPE_WIDGET "widgetapp"
#define STATUS_FOREGROUND "fg"
#define STATUS_BACKGROUND "bg"

static int __app_event_converter[APPCORE_BASE_EVENT_MAX] = {
	[APP_EVENT_LOW_MEMORY] = APPCORE_BASE_EVENT_LOW_MEMORY,
	[APP_EVENT_LOW_BATTERY] = APPCORE_BASE_EVENT_LOW_BATTERY,
	[APP_EVENT_LANGUAGE_CHANGED] = APPCORE_BASE_EVENT_LANG_CHANGE,
	[APP_EVENT_DEVICE_ORIENTATION_CHANGED]
			= APPCORE_BASE_EVENT_DEVICE_ORIENTATION_CHANGED,
	[APP_EVENT_REGION_FORMAT_CHANGED] = APPCORE_BASE_EVENT_REGION_CHANGE,
	[APP_EVENT_SUSPENDED_STATE_CHANGED]
			= APPCORE_BASE_EVENT_SUSPENDED_STATE_CHANGE,
};

struct app_event_info {
	app_event_type_e type;
	void *value;
};

struct app_event_handler {
	app_event_type_e type;
	app_event_cb cb;
	void *data;
	void *raw;
};

struct widget_foreach_context {
	widget_base_instance_cb callback;
	void *data;
};

typedef struct _widget_base_context {
	widget_base_ops ops;
	void *data;
	int argc;
	char **argv;
	GList *classes;
} widget_base_context;

typedef struct _widget_base_instance_data {
	bundle *args;
	char *id;
	char *content;
	void *tag;
	double period;
	guint periodic_timer;
	bool pending_update;
	char *pending_content;
	void *user_data;
} widget_base_instance_data;

static widget_base_context __context;
static char *__appid;
static char *__package_id;
static bool __fg_signal;
static char *__viewer_endpoint;
static bool __is_permanent;
static void __call_update_cb(const char *class_id, const char *id, int force,
		const char *content_raw);

static gboolean __timeout_cb(gpointer user_data)
{
	widget_base_instance_data *data =
			(widget_base_instance_data *)user_data;
	appcore_multiwindow_base_instance_h cxt;
	const char *class_id;

	cxt = appcore_multiwindow_base_instance_find(data->id);

	if (!cxt) {
		LOGE("Can't find the instance");
		return G_SOURCE_REMOVE;
	}

	if (appcore_multiwindow_base_instance_is_resumed(cxt)) {
		LOGD("Periodic update!");
		class_id = appcore_multiwindow_base_instance_get_class_id(cxt);
		__call_update_cb(class_id, data->id, 0, NULL);
	} else {
		data->pending_update = true;
		if (data->periodic_timer) {
			LOGD("Remove timer!");
			g_source_remove(data->periodic_timer);
			data->periodic_timer = 0;
		}
	}

	return G_SOURCE_CONTINUE;
}

static bool __is_widget_feature_enabled(void)
{
	static bool feature = false;
	static bool retrieved = false;
	int ret;

	if (retrieved == true)
		return feature;

	ret = system_info_get_platform_bool(FEATURE_SHELL_APPWIDGET, &feature);
	if (ret != SYSTEM_INFO_ERROR_NONE) {
		LOGE("failed to get system info"); /* LCOV_EXCL_LINE */
		return false; /* LCOV_EXCL_LINE */
	}

	retrieved = true;

	return feature;
}

/* LCOV_EXCL_START */
static void __on_poweroff(keynode_t *key, void *data)
{
	int val;

	val = vconf_keynode_get_int(key);
	switch (val) {
	case VCONFKEY_SYSMAN_POWER_OFF_DIRECT:
	case VCONFKEY_SYSMAN_POWER_OFF_RESTART:
		LOGI("power off changed: %d", val);
		widget_base_exit();
		break;
	case VCONFKEY_SYSMAN_POWER_OFF_NONE:
	case VCONFKEY_SYSMAN_POWER_OFF_POPUP:
	default:
		/* DO NOTHING */
		break;
	}
}
/* LCOV_EXCL_STOP */

static void __check_empty_instance(void)
{
	int cnt = appcore_multiwindow_base_instance_get_cnt();

	if (cnt == 0)
		widget_base_exit();
}

static void __instance_drop(appcore_multiwindow_base_instance_h instance_h)
{
	widget_base_instance_data *data;

	data = appcore_multiwindow_base_instance_get_extra(instance_h);
	appcore_multiwindow_base_instance_drop(instance_h);
	free(data->pending_content);
	free(data->content);
	free(data->id);
	free(data);
	__check_empty_instance();
}

static gint __comp_class(gconstpointer a, gconstpointer b)
{
	const widget_base_class *cls = a;

	return strcmp(cls->id, b);
}

static widget_base_class *__get_class(const char *class_id)
{
	widget_base_class *cls;
	GList *class_node;

	class_node = g_list_find_custom(__context.classes, class_id,
			__comp_class);
	if (class_node == NULL) {
		LOGE("empty classes");
		return NULL;
	}
	cls = (widget_base_class *)class_node->data;

	return cls;
}

static int __send_lifecycle_event(const char *class_id, const char *instance_id,
	int status)
{
	bundle *b = bundle_create();
	int ret;

	if (b == NULL) {
		LOGE("out of memory"); /* LCOV_EXCL_LINE */
		return -1; /* LCOV_EXCL_LINE */
	}

	bundle_add_str(b, AUL_K_WIDGET_ID, class_id);
	bundle_add_str(b, AUL_K_WIDGET_INSTANCE_ID, instance_id);
	bundle_add_byte(b, AUL_K_WIDGET_STATUS, &status, sizeof(int));
	bundle_add_str(b, AUL_K_PKGID, __package_id);

	LOGD("send lifecycle %s(%d)", instance_id, status);
	ret = aul_app_com_send("widget.status", b);
	if (ret < 0)
		LOGE("send lifecycle error:%d", ret); /* LCOV_EXCL_LINE */

	bundle_free(b);

	return ret;
}

static int __send_update_status(const char *class_id, const char *instance_id,
	int status, int err, bundle *extra)
{
	bundle *b;
	int lifecycle = -1;
	bundle_raw *raw = NULL;
	int len;
	char err_str[256];

	b = bundle_create();
	if (!b) {
		LOGE("out of memory"); /* LCOV_EXCL_LINE */
		return -1; /* LCOV_EXCL_LINE */
	}

	if (err < 0) {
		snprintf(err_str, sizeof(err_str), "%d", err);
		bundle_add_str(b, AUL_K_WIDGET_ERROR_CODE, err_str);
	}

	bundle_add_str(b, AUL_K_WIDGET_ID, class_id);
	bundle_add_str(b, AUL_K_WIDGET_INSTANCE_ID, instance_id);
	bundle_add_byte(b, AUL_K_WIDGET_STATUS, &status, sizeof(int));

	if (extra) {
		bundle_encode(extra, &raw, &len);
		bundle_add_str(b, WIDGET_K_CONTENT_INFO, (const char *)raw);
		aul_widget_instance_add(class_id, instance_id);
	}

	LOGD("send update %s(%d) to %s", instance_id, status, __viewer_endpoint);
	aul_app_com_send(__viewer_endpoint, b);

	switch (status) {
	case WIDGET_INSTANCE_EVENT_CREATE:
		lifecycle = WIDGET_LIFE_CYCLE_EVENT_CREATE;
		break;
	case WIDGET_INSTANCE_EVENT_DESTROY:
		lifecycle = WIDGET_LIFE_CYCLE_EVENT_DESTROY;
		break;
	case WIDGET_INSTANCE_EVENT_PAUSE:
		lifecycle = WIDGET_LIFE_CYCLE_EVENT_PAUSE;
		break;
	case WIDGET_INSTANCE_EVENT_RESUME:
		lifecycle = WIDGET_LIFE_CYCLE_EVENT_RESUME;
		break;
	}

	if (lifecycle > -1)
		__send_lifecycle_event(class_id, instance_id, lifecycle);

	bundle_free(b);
	if (raw)
		free(raw);

	return 0;
}

static void __control_create(const char *class_id, const char *id, bundle *b)
{
	widget_base_instance_data *data;
	char *content = NULL;

	if (appcore_multiwindow_base_instance_find(id)) {
		LOGE("Already exist id (%s)", id);
		return;
	}

	data = (widget_base_instance_data *)
			calloc(1, sizeof(widget_base_instance_data));
	if (!data) {
		LOGE("Out of memory");
		return;
	}

	data->id = strdup(id);
	data->args = b;

	/* call stub create */
	appcore_multiwindow_base_instance_run(class_id, id, data);
	data->args = NULL;
	bundle_get_str(b, WIDGET_K_CONTENT_INFO, &content);
	if (content)
		data->content = strdup(content);

}

static void __control_resume(const char *class_id, const char *id, bundle *b)
{
	appcore_multiwindow_base_instance_h cxt;

	cxt = appcore_multiwindow_base_instance_find(id);
	if (!cxt) {
		LOGE("context not found: %s", id);
		return;
	}

	/* call stub resume */
	appcore_multiwindow_base_instance_resume(cxt);
}

static void __control_pause(const char *class_id, const char *id, bundle *b)
{
	appcore_multiwindow_base_instance_h instance_h;

	instance_h = appcore_multiwindow_base_instance_find(id);

	if (!instance_h) {
		LOGE("instance not found: %s", id);
		return;
	}

	/* call stub pause */
	appcore_multiwindow_base_instance_pause(instance_h);
}

static void __control_resize(const char *class_id, const char *id, bundle *b)
{
	appcore_multiwindow_base_instance_h instance_h;
	char *remain = NULL;
	char *w_str = NULL;
	char *h_str = NULL;
	int w = 0;
	int h = 0;
	void *class_data;
	widget_base_class *cls;
	const appcore_multiwindow_base_class *raw_cls;

	instance_h = appcore_multiwindow_base_instance_find(id);
	if (!instance_h) {
		LOGE("context not found: %s", id);
		return;
	}

	raw_cls = appcore_multiwindow_base_instance_get_class(instance_h);
	if (!raw_cls)
		return;

	cls = __get_class(class_id);
	if (cls == NULL) {
		LOGE("class not found: %s", class_id);
		return;
	}
	class_data = raw_cls->data;
	bundle_get_str(b, WIDGET_K_WIDTH, &w_str);
	bundle_get_str(b, WIDGET_K_HEIGHT, &h_str);

	if (w_str)
		w = (int)g_ascii_strtoll(w_str, &remain, 10);

	if (h_str)
		h = (int)g_ascii_strtoll(h_str, &remain, 10);

	if (cls->ops.resize)
		cls->ops.resize(instance_h, w, h, class_data);

	LOGD("%s is resized to %dx%d", id, w, h);
	__send_update_status(class_id, id,
		WIDGET_INSTANCE_EVENT_SIZE_CHANGED, 0, NULL);
}

static void __call_update_cb(const char *class_id, const char *id, int force,
		const char *content_raw)
{
	void *class_data;
	widget_base_class *cls;
	const appcore_multiwindow_base_class *raw_cls;
	appcore_multiwindow_base_instance_h instance_h;
	bundle *content = NULL;

	instance_h = appcore_multiwindow_base_instance_find(id);
	if (!instance_h) {
		LOGE("context not found: %s", id);
		return;
	}

	raw_cls = appcore_multiwindow_base_instance_get_class(instance_h);
	if (!raw_cls) {
		LOGE("class is NULL");
		return;
	}

	class_data = raw_cls->data;
	cls = __get_class(class_id);
	if (cls == NULL) {
		LOGE("class not found: %s", class_id);
		return;
	}

	if (!cls->ops.update) {
		LOGE("update callback is NULL");
		return;
	}

	if (content_raw) {
		content = bundle_decode((const bundle_raw *)content_raw,
				strlen(content_raw));
	}

	if (cls->ops.update)
		cls->ops.update(instance_h, content, force, class_data);

	__send_update_status(class_id, id,
		WIDGET_INSTANCE_EVENT_UPDATE, 0, NULL);
	LOGD("updated:%s", id);

	if (content)
		bundle_free(content);
}

static void __update_pending_content(
		appcore_multiwindow_base_instance_h instance_h,
		const char *content_raw)
{
	widget_base_instance_data *data;

	data = (widget_base_instance_data *)
			appcore_multiwindow_base_instance_get_extra(instance_h);

	if (data->pending_content) {
		free(data->pending_content);
		data->pending_content = NULL;
	}

	if (content_raw) {
		data->pending_content = strdup(content_raw);
		if (data->pending_content == NULL)
			LOGW("Out of memory");
	}

	data->pending_update = true;
}

static void __update_process(const char *class_id, const char *id,
		appcore_multiwindow_base_instance_h instance_h, void *data)
{
	char *content_raw = NULL;
	char *force_str = NULL;
	int force;
	bundle *b = data;

	if (!b) {
		LOGE("bundle is NULL");
		return;
	}

	bundle_get_str(b, WIDGET_K_FORCE, &force_str);

	if (force_str && strcmp(force_str, "true") == 0)
		force = 1;
	else
		force = 0;

	bundle_get_str(b, WIDGET_K_CONTENT_INFO, &content_raw);
	if (!appcore_multiwindow_base_instance_is_resumed(instance_h) && !force)
		__update_pending_content(instance_h, content_raw);
	else
		__call_update_cb(class_id, id, force, content_raw);
}

static void __control_update(const char *class_id, const char *id, bundle *b)
{
	appcore_multiwindow_base_instance_h instance_h;

	if (!id) {
		appcore_multiwindow_base_instance_foreach(class_id,
				__update_process, b);
		return;
	}

	instance_h = appcore_multiwindow_base_instance_find(id);
	if (!instance_h) {
		LOGE("context not found: %s", id);
		return;
	}

	__update_process(class_id, id, instance_h, b);
}

static void __control_destroy(const char *class_id, const char *id, bundle *b)
{
	appcore_multiwindow_base_instance_h instance_h;
	widget_base_instance_data *data;

	instance_h = appcore_multiwindow_base_instance_find(id);
	if (!instance_h) {
		LOGE("could not find widget obj: %s, clear amd info", id);
		aul_widget_instance_del(class_id, id);
		return;
	}

	data = (widget_base_instance_data *)
			appcore_multiwindow_base_instance_get_extra(instance_h);
	data->args = b;

	/* call stub terminate */
	appcore_multiwindow_base_instance_exit(instance_h);
	free(data->pending_content);
	free(data->content);
	free(data->id);
	free(data);
	__check_empty_instance();
}

static void __control_change_period(const char *class_id, const char *id,
		bundle *b)
{
	appcore_multiwindow_base_instance_h instance_h;
	widget_base_instance_data *data;
	double *period = NULL;
	size_t size;
	int ret;

	instance_h = appcore_multiwindow_base_instance_find(id);
	if (!instance_h) {
		LOGE("context not found: %s", id);
		return;
	}

	data = (widget_base_instance_data *)
			appcore_multiwindow_base_instance_get_extra(instance_h);

	if (!data) {
		LOGE("could not find instance data: %s", id);
		return;
	}

	if (data->periodic_timer) {
		LOGD("Remove timer!");
		g_source_remove(data->periodic_timer);
		data->periodic_timer = 0;
	}

	ret = bundle_get_byte(b, WIDGET_K_PERIOD, (void **)&period, &size);
	if (ret == BUNDLE_ERROR_NONE)
		data->period = *period;

	if (data->period > 0) {
		LOGD("Restart timer!");
		data->periodic_timer = g_timeout_add_seconds(data->period,
				__timeout_cb, data);
	}

	return;
}

static int __multiwindow_create(void *data)
{
	char pkgid[256] = {0, };
	int ret = 0;

	appcore_multiwindow_base_on_create();
	app_get_id(&__appid);
	if (aul_app_get_pkgid_bypid(getpid(), pkgid, sizeof(pkgid)) == 0)
		__package_id = strdup(pkgid);

	if (!__package_id || !__appid) {
		LOGE("__package_id is NULL");
		return -1;
	}

	screen_connector_provider_init();
	vconf_notify_key_changed(VCONFKEY_SYSMAN_POWER_OFF_STATUS,
			__on_poweroff, NULL);


	if (__context.ops.create)
		ret = __context.ops.create(data);

	LOGD("widget base is created");
	return ret;
}

static int __multiwindow_terminate(void *data)
{
	if (__context.ops.terminate)
		__context.ops.terminate(data);

	vconf_ignore_key_changed(VCONFKEY_SYSMAN_POWER_OFF_STATUS,
			__on_poweroff);
	screen_connector_provider_fini();

	if (__viewer_endpoint) {
		free(__viewer_endpoint);
		__viewer_endpoint = NULL;
	}

	if (__package_id) {
		free(__package_id);
		__package_id = NULL;
	}

	if (__appid) {
		free(__appid);
		__appid = NULL;
	}

	appcore_multiwindow_base_on_terminate();

	LOGD("widget base is terminated");
	return 0;
}

static int __multiwindow_control(bundle *b, void *data)
{
	char *class_id = NULL;
	char *id = NULL;
	char *operation = NULL;

	appcore_multiwindow_base_on_control(b);
	bundle_get_str(b, WIDGET_K_CLASS, &class_id);
	/* for previous version compatibility, use appid for default class id */
	if (class_id == NULL)
		class_id = __appid;

	bundle_get_str(b, AUL_K_WIDGET_INSTANCE_ID, &id);
	bundle_get_str(b, WIDGET_K_OPERATION, &operation);

	if (!operation) {
		LOGE("operation is NULL");
		return 0;
	}

	if (strcmp(operation, "create") == 0)
		__control_create(class_id, id, b);
	else if (strcmp(operation, "resize") == 0)
		__control_resize(class_id, id, b);
	else if (strcmp(operation, "update") == 0)
		__control_update(class_id, id, b);
	else if (strcmp(operation, "destroy") == 0)
		__control_destroy(class_id, id, b);
	else if (strcmp(operation, "resume") == 0)
		__control_resume(class_id, id, b);
	else if (strcmp(operation, "pause") == 0)
		__control_pause(class_id, id, b);
	else if (strcmp(operation, "terminate") == 0)
		__control_destroy(class_id, id, b);
	else if (strcmp(operation, "period") == 0)
		__control_change_period(class_id, id, b);

	return 0;
}

static void __inst_resume_cb(const char *class_id, const char *id,
		appcore_multiwindow_base_instance_h cxt, void *data)
{
	__control_resume(class_id, id, data);
}

static void __get_content(bundle *b)
{
	char *instance_id = NULL;
	appcore_multiwindow_base_instance_h cxt;
	widget_base_instance_data * we;

	bundle_get_str(b, AUL_K_WIDGET_INSTANCE_ID, &instance_id);
	if (!instance_id) {
		LOGE("instance id is NULL");
		return;
	}

	cxt = appcore_multiwindow_base_instance_find(instance_id);
	if (!cxt) {
		LOGE("could not find widget obj: %s", instance_id);
		return;
	}

	we = appcore_multiwindow_base_instance_get_extra(cxt);
	if (!we) {
		LOGE("widget extra is NULL");
		return;
	}

	if (we->content) {
		bundle_add_str(b, AUL_K_WIDGET_CONTENT_INFO, we->content);
		LOGD("content info of %s found", instance_id);
	} else {
		bundle_add_str(b, AUL_K_WIDGET_CONTENT_INFO, "");
		LOGD("empty content info added");
	}
}

static int __multiwindow_receive(aul_type type, bundle *b, void *data)
{
	appcore_multiwindow_base_on_receive(type, b);

	switch (type) {
	case AUL_RESUME:
		appcore_multiwindow_base_instance_foreach_full(
				__inst_resume_cb, b);
		break;
	case AUL_TERMINATE:
		widget_base_exit();
		break;
	case AUL_WIDGET_CONTENT:
		__get_content(b);
		break;
	default:
		break;
	}

	return 0;
}

static void __multiwindow_init(int argc, char **argv, void *data)
{
	if (__context.ops.init)
		__context.ops.init(argc, argv, data);
}

static void __multiwindow_finish(void)
{
	if (__context.ops.finish) {
		__context.ops.finish();
		/* Check Loader case */
		if (getenv("AUL_LOADER_INIT")) {
			unsetenv("AUL_LOADER_INIT");
			__context.ops.finish();
		}
	}
}

static void __multiwindow_run(void *data)
{
	if (__context.ops.run)
		__context.ops.run(data);
}

static void __multiwindow_exit(void *data)
{
	if (__context.ops.exit)
		__context.ops.exit(data);
}

static void __multiwindow_trim_memory(void *data)
{
	if (__context.ops.trim_memory)
		__context.ops.trim_memory(data);
}

EXPORT_API int widget_base_exit(void)
{
	int ret;

	appcore_multiwindow_base_exit();
	if (appcore_multiwindow_base_instance_get_cnt() == 0 && __is_permanent) {
		ret = aul_notify_exit();
		aul_widget_write_log(LOG_TAG, "[%s:%d] permanent exit : %d",
			__FUNCTION__, __LINE__, ret);
	}

	return 0;
}

static gboolean __finish_event_cb(gpointer user_data)
{
	appcore_multiwindow_base_instance_h cxt = user_data;
	bundle *b;
	const char *id;
	const char *class_id;

	if (!cxt) {
		LOGE("user_data is NULL");
		return FALSE;
	}

	id = appcore_multiwindow_base_instance_get_id(cxt);
	class_id = appcore_multiwindow_base_instance_get_class_id(cxt);
	b = bundle_create();

	if (!b) {
		LOGE("Out-of-memory");
		return FALSE;
	}

	bundle_add_str(b, WIDGET_K_OPERATION, "terminate");
	__control_destroy(class_id, id, b);
	bundle_free(b);

	return FALSE;
}

EXPORT_API int widget_base_terminate_context(widget_base_instance_h context)
{
	if (!__is_widget_feature_enabled()) {
		LOGE("not supported"); /* LCOV_EXCL_LINE */
		return WIDGET_ERROR_NOT_SUPPORTED; /* LCOV_EXCL_LINE */
	}

	if (!context) {
		LOGE("context is null");
		return WIDGET_ERROR_INVALID_PARAMETER;
	}

	g_idle_add(__finish_event_cb, context);

	return WIDGET_ERROR_NONE;
}

static void __inst_full_cb(const char *class_id, const char *id,
		appcore_multiwindow_base_instance_h cxt, void *data)
{
	struct widget_foreach_context *foreach_context = data;

	if (!data)
		return;

	if (foreach_context->callback)
		foreach_context->callback(cxt, foreach_context->data);
}

EXPORT_API int widget_base_foreach_context(widget_base_instance_cb cb, void *data)
{
	struct widget_foreach_context foreach_context;

	if (!__is_widget_feature_enabled()) {
		LOGE("not supported"); /* LCOV_EXCL_LINE */
		return WIDGET_ERROR_NOT_SUPPORTED; /* LCOV_EXCL_LINE */
	}

	if (!cb) {
		LOGE("callback is NULL");
		return WIDGET_ERROR_INVALID_PARAMETER;
	}

	foreach_context.callback = cb;
	foreach_context.data = data;
	appcore_multiwindow_base_instance_foreach_full(__inst_full_cb, &foreach_context);

	return WIDGET_ERROR_NONE;
}

static int __event_cb(void *event, void *data)
{
	app_event_handler_h handler = data;

	struct app_event_info app_event;

	app_event.type = handler->type;
	app_event.value = event;

	if (handler->cb)
		handler->cb(&app_event, handler->data);

	return 0;
}

EXPORT_API int widget_base_add_event_handler(app_event_handler_h *event_handler,
					app_event_type_e event_type,
					app_event_cb callback,
					void *user_data)
{
	int r;
	bool feature;
	app_event_handler_h handler;

	r = system_info_get_platform_bool(FEATURE_SHELL_APPWIDGET, &feature);
	if (r < 0)
		return WIDGET_BASE_ERROR_FAULT;

	if (!feature)
		return WIDGET_BASE_ERROR_NOT_SUPPORTED;

	if (event_handler == NULL || callback == NULL)
		return WIDGET_BASE_ERROR_INVALID_PARAMETER;

	if (event_type < APP_EVENT_LOW_MEMORY
	    || event_type > APP_EVENT_REGION_FORMAT_CHANGED)
		return WIDGET_BASE_ERROR_INVALID_PARAMETER;

	if (event_type == APP_EVENT_DEVICE_ORIENTATION_CHANGED)
		return WIDGET_BASE_ERROR_NOT_SUPPORTED;


	handler = calloc(1, sizeof(struct app_event_handler));
	if (!handler)
		return WIDGET_BASE_ERROR_OUT_OF_MEMORY;

	handler->type = event_type;
	handler->cb = callback;
	handler->data = user_data;
	handler->raw = appcore_base_add_event(
			__app_event_converter[event_type], __event_cb, handler);
	*event_handler = handler;

	return WIDGET_BASE_ERROR_NONE;
}

EXPORT_API int widget_base_remove_event_handler(app_event_handler_h
						event_handler)
{
	int r;
	bool feature;
	app_event_type_e type;

	r = system_info_get_platform_bool(FEATURE_SHELL_APPWIDGET, &feature);
	if (r < 0)
		return WIDGET_BASE_ERROR_FAULT;

	if (!feature)
		return WIDGET_BASE_ERROR_NOT_SUPPORTED;

	if (event_handler == NULL)
		return WIDGET_BASE_ERROR_INVALID_PARAMETER;

	type = event_handler->type;
	if (type < APP_EVENT_LOW_MEMORY ||
			type > APP_EVENT_REGION_FORMAT_CHANGED)
		return WIDGET_BASE_ERROR_INVALID_PARAMETER;

	r = appcore_base_remove_event(event_handler->raw);
	if (r < 0)
		return WIDGET_BASE_ERROR_INVALID_PARAMETER;

	free(event_handler);

	return WIDGET_BASE_ERROR_NONE;
}

EXPORT_API int widget_base_context_set_content_info(
		widget_base_instance_h context,
		bundle *content_info)
{
	int ret = 0;
	bundle_raw *raw = NULL;
	int len;
	const char *id;
	const char *class_id;
	widget_base_instance_data *data;
	appcore_multiwindow_base_instance_h instance_h;

	if (!__is_widget_feature_enabled()) {
		LOGE("not supported"); /* LCOV_EXCL_LINE */
		return WIDGET_BASE_ERROR_NOT_SUPPORTED; /* LCOV_EXCL_LINE */
	}

	if (!context || !content_info)
		return WIDGET_BASE_ERROR_INVALID_PARAMETER;

	instance_h = (appcore_multiwindow_base_instance_h)context;
	id = appcore_multiwindow_base_instance_get_id(instance_h);
	class_id = appcore_multiwindow_base_instance_get_class_id(instance_h);
	data = appcore_multiwindow_base_instance_get_extra(instance_h);

	if (!class_id || !id || !data)
		return WIDGET_BASE_ERROR_FAULT;

	ret = __send_update_status(class_id, id,
			WIDGET_INSTANCE_EVENT_EXTRA_UPDATED, 0, content_info);

	if (data->content)
		free(data->content);

	bundle_encode(content_info, &raw, &len);
	if (raw)
		data->content = strdup((const char *)raw);
	else
		data->content = NULL;

	free(raw);
	if (ret < 0) {
		/* LCOV_EXCL_START */
		LOGE("failed to send content info: %s of %s (%d)", id,
				class_id, ret);
		return WIDGET_BASE_ERROR_IO_ERROR;
		/* LCOV_EXCL_STOP */
	}

	return WIDGET_BASE_ERROR_NONE;
}

EXPORT_API int widget_base_context_get_tag(widget_base_instance_h context, void **tag)
{
	appcore_multiwindow_base_instance_h instance_h;
	widget_base_instance_data *data;

	if (!__is_widget_feature_enabled()) {
		LOGE("not supported"); /* LCOV_EXCL_LINE */
		return WIDGET_BASE_ERROR_NOT_SUPPORTED; /* LCOV_EXCL_LINE */
	}

	if (!context || !tag) {
		LOGE("Invalid parameter");
		return WIDGET_BASE_ERROR_INVALID_PARAMETER;
	}

	instance_h = (appcore_multiwindow_base_instance_h)context;
	data = (widget_base_instance_data *)
			appcore_multiwindow_base_instance_get_extra(instance_h);

	if (!data) {
		LOGE("Invalid parameter");
		return WIDGET_ERROR_INVALID_PARAMETER;
	}

	*tag = data->tag;

	return WIDGET_BASE_ERROR_NONE;
}

EXPORT_API int widget_base_context_set_tag(widget_base_instance_h context, void *tag)
{
	appcore_multiwindow_base_instance_h instance_h;
	widget_base_instance_data *data;

	if (!__is_widget_feature_enabled()) {
		LOGE("not supported"); /* LCOV_EXCL_LINE */
		return WIDGET_BASE_ERROR_NOT_SUPPORTED; /* LCOV_EXCL_LINE */
	}

	if (!context) {
		LOGE("Invalid parameter");
		return WIDGET_BASE_ERROR_INVALID_PARAMETER;
	}

	instance_h = (appcore_multiwindow_base_instance_h)context;
	data = (widget_base_instance_data *)
			appcore_multiwindow_base_instance_get_extra(instance_h);
	data->tag = tag;

	return WIDGET_BASE_ERROR_NONE;
}

EXPORT_API void *widget_base_context_get_user_data(
		widget_base_instance_h context)
{
	appcore_multiwindow_base_instance_h instance_h;
	widget_base_instance_data *data;

	if (!__is_widget_feature_enabled()) {
		LOGE("not supported"); /* LCOV_EXCL_LINE */
		return NULL; /* LCOV_EXCL_LINE */
	}

	if (!context) {
		LOGE("Invalid parameter");
		return NULL;
	}

	instance_h = (appcore_multiwindow_base_instance_h)context;
	data = (widget_base_instance_data *)
			appcore_multiwindow_base_instance_get_extra(instance_h);

	return data->user_data;
}


EXPORT_API int widget_base_context_set_user_data(
		widget_base_instance_h context, void *user_data)
{
	appcore_multiwindow_base_instance_h instance_h;
	widget_base_instance_data *data;

	if (!__is_widget_feature_enabled()) {
		LOGE("not supported"); /* LCOV_EXCL_LINE */
		return WIDGET_BASE_ERROR_NOT_SUPPORTED; /* LCOV_EXCL_LINE */
	}

	if (!context) {
		LOGE("Invalid parameter");
		return WIDGET_BASE_ERROR_INVALID_PARAMETER;
	}

	instance_h = (appcore_multiwindow_base_instance_h)context;
	data = (widget_base_instance_data *)
			appcore_multiwindow_base_instance_get_extra(instance_h);
	data->user_data = user_data;

	return WIDGET_BASE_ERROR_NONE;
}

EXPORT_API int widget_base_context_get_id(widget_base_instance_h context, char **id)
{
	appcore_multiwindow_base_instance_h instance_h;

	if (!__is_widget_feature_enabled()) {
		LOGE("not supported"); /* LCOV_EXCL_LINE */
		return WIDGET_BASE_ERROR_NOT_SUPPORTED; /* LCOV_EXCL_LINE */
	}

	instance_h = (appcore_multiwindow_base_instance_h)context;
	*id = (char *)appcore_multiwindow_base_instance_get_id(instance_h);

	return WIDGET_BASE_ERROR_NONE;
}

EXPORT_API const char *widget_base_get_viewer_endpoint()
{
	return __viewer_endpoint;
}

EXPORT_API int widget_base_init(widget_base_ops ops, int argc, char **argv,
		void *data)
{
	bundle *kb;
	char *viewer_endpoint = NULL;
	appcore_multiwindow_base_ops raw_ops
			= appcore_multiwindow_base_get_default_ops();

	__context.ops = ops;
	__context.argc = argc;
	__context.argv = argv;
	__context.data = data;

	/* override methods */
	raw_ops.base.create = __multiwindow_create;
	raw_ops.base.control = __multiwindow_control;
	raw_ops.base.terminate = __multiwindow_terminate;
	raw_ops.base.receive = __multiwindow_receive;
	raw_ops.base.init = __multiwindow_init;
	raw_ops.base.finish = __multiwindow_finish;
	raw_ops.base.run = __multiwindow_run;
	raw_ops.base.exit = __multiwindow_exit;
	raw_ops.base.trim_memory = __multiwindow_trim_memory;

	if (!__is_widget_feature_enabled()) {
		LOGE("not supported"); /* LCOV_EXCL_LINE */
		return WIDGET_ERROR_NOT_SUPPORTED; /* LCOV_EXCL_LINE */
	}

	kb = bundle_import_from_argv(argc, argv);
	if (kb) {
		bundle_get_str(kb, AUL_K_WIDGET_VIEWER, &viewer_endpoint);
		if (viewer_endpoint) {
			LOGD("viewer endpoint :%s", viewer_endpoint);
			__viewer_endpoint = strdup(viewer_endpoint);
		} else {
			LOGE("endpoint is missing");
		}

		bundle_free(kb);
	} else {
		LOGE("failed to get launch argv"); /* LCOV_EXCL_LINE */
		return WIDGET_ERROR_FAULT;
	}

	if (appcore_multiwindow_base_init(raw_ops, argc, argv, data) < 0)
	       return WIDGET_ERROR_FAULT;

	return WIDGET_ERROR_NONE;
}

static int __on_create(void *data)
{
	return widget_base_on_create();
}

static int __on_terminate(void *data)
{
	return widget_base_on_terminate();
}

static void __on_init(int argc, char **argv, void *data)
{
	widget_base_on_init(argc, argv);
}

static void __on_finish(void)
{
	widget_base_on_finish();
}

static void __on_run(void *data)
{
	widget_base_on_run();
}

static void __on_exit(void *data)
{
	widget_base_on_exit();
}

static void __on_trim_memory(void *data)
{
	widget_base_on_trim_memory();
}

EXPORT_API int widget_base_on_create(void)
{
	appcore_multiwindow_base_on_create();

	return 0;
}

EXPORT_API int widget_base_on_terminate(void)
{
	appcore_multiwindow_base_on_terminate();

	return 0;
}

EXPORT_API int widget_base_on_init(int argc, char **argv)
{
	return 0;
}

EXPORT_API void widget_base_on_finish(void)
{
}

EXPORT_API void widget_base_on_run(void)
{
}

EXPORT_API void widget_base_on_exit(void)
{
}

EXPORT_API int widget_base_on_trim_memory(void)
{
	appcore_multiwindow_base_on_trim_memory();

	return 0;
}

EXPORT_API widget_base_ops widget_base_get_default_ops(void)
{
	widget_base_ops ops;

	/* override methods */
	ops.create = __on_create;
	ops.terminate = __on_terminate;
	ops.init = __on_init;
	ops.finish = __on_finish;
	ops.run = __on_run;
	ops.exit = __on_exit;
	ops.trim_memory = __on_trim_memory;

	return ops;
}

static void __free_class(gpointer data)
{
	widget_base_class *cls = data;

	free(cls->id);
	free(cls);
}

EXPORT_API void widget_base_fini(void)
{
	appcore_multiwindow_base_fini();
	g_list_free_full(__context.classes, __free_class);
	__context.classes = NULL;
}

EXPORT_API int widget_base_context_window_bind(
		widget_base_instance_h instance_h, const char *id,
		Ecore_Wl2_Window *wl_win)
{
	struct wl_surface *surface;

	surface = ecore_wl2_window_surface_get(wl_win);
	if (surface == NULL) {
		LOGE("failed to get surface"); /* LCOV_EXCL_LINE */
		return WIDGET_BASE_ERROR_FAULT; /* LCOV_EXCL_LINE */
	}

	screen_connector_provider_remote_enable(id, surface);
	appcore_multiwindow_base_window_bind(instance_h, wl_win);

	return WIDGET_BASE_ERROR_NONE;
}

static int __class_on_create(widget_base_instance_h instance_h, bundle *content,
		int w, int h, void *class_data)
{
	return widget_base_class_on_create(instance_h, content, w, h);
}

static int __class_on_resume(widget_base_instance_h instance_h,	void *class_data)
{
	return widget_base_class_on_resume(instance_h);
}

static int __class_on_pause(widget_base_instance_h instance_h,
		void *class_data)
{
	return widget_base_class_on_pause(instance_h);
}

static int __class_on_resize(widget_base_instance_h instance_h, int w, int h,
		void *class_data)
{
	return widget_base_class_on_resize(instance_h, w, h);
}

static int __class_on_update(widget_base_instance_h instance_h, bundle *content,
		int force, void *class_data)
{
	return widget_base_class_on_update(instance_h, content, force);
}

static int __class_on_destroy(widget_base_instance_h instance_h,
		widget_base_destroy_type_e reason, bundle *content,
		void *class_data)
{
	return widget_base_class_on_destroy(instance_h, reason, content);
}

static void __multiwindow_instance_create(
		appcore_multiwindow_base_instance_h instance_h,
		void *class_data)
{
	widget_base_instance_data *instance_data;
	bundle *b;
	bundle *content_info = NULL;
	char *id = NULL;
	char *class_id = NULL;
	char *operation = NULL;
	char *content = NULL;
	char *w_str = NULL;
	char *h_str = NULL;
	char *remain = NULL;
	int w = 0;
	int h = 0;
	int ret = -1;
	widget_base_class *cls;
	double *period = NULL;
	size_t size;

	appcore_multiwindow_base_class_on_create(instance_h);
	instance_data = appcore_multiwindow_base_instance_get_extra(instance_h);
	b = instance_data->args;

	bundle_get_str(b, WIDGET_K_CLASS, &class_id);
	/* for previous version compatibility, use appid for default class id */
	if (class_id == NULL)
		class_id = __appid;

	cls = __get_class(class_id);
	if (cls == NULL) {
		LOGE("class not found: %s", class_id);
		return;
	}

	bundle_get_str(b, AUL_K_WIDGET_INSTANCE_ID, &id);
	bundle_get_str(b, WIDGET_K_OPERATION, &operation);

	if (!operation) {
		LOGE("no operation provided");
		return;
	}

	bundle_get_str(b, WIDGET_K_CONTENT_INFO, &content);
	bundle_get_str(b, WIDGET_K_WIDTH, &w_str);
	bundle_get_str(b, WIDGET_K_HEIGHT, &h_str);

	if (w_str)
		w = (int)g_ascii_strtoll(w_str, &remain, 10);

	if (h_str)
		h = (int)g_ascii_strtoll(h_str, &remain, 10);

	if (content)
		content_info = bundle_decode((const bundle_raw *)content,
				strlen(content));

	if (cls->ops.create)
		ret = cls->ops.create(instance_h, content_info, w, h, class_data);

	if (ret < 0) {
		LOGW("Create callback returns error(%d)", ret);
		ret = __send_update_status(class_id, id,
				WIDGET_INSTANCE_EVENT_CREATE_ABORTED, ret, NULL);
		if (ret < 0)
			LOGE("Fail to send abort status (%d) ", ret);
		__instance_drop(instance_h);
	} else {
		LOGD("%s is created", id);
		ret = __send_update_status(class_id, id,
			WIDGET_INSTANCE_EVENT_CREATE, 0, NULL);
		if (ret < 0)
			LOGE("Fail to send create status (%d) ", ret);

		aul_widget_instance_add(class_id, id);

		ret = bundle_get_byte(b, WIDGET_K_PERIOD, (void **)&period,
				&size);
		if (ret == BUNDLE_ERROR_NONE && *period > 0) {
			LOGI("set periodic update timer (%lf)", *period);
			instance_data->period = *period;
			instance_data->periodic_timer = g_timeout_add_seconds(
					instance_data->period,
					__timeout_cb, instance_data);
		}
	}

	if (content_info)
		bundle_free(content_info);
}

static void __multiwindow_instance_resume(
		appcore_multiwindow_base_instance_h instance_h,
		void *class_data)
{
	const char *id;
	const char *class_id;
	widget_base_class *cls;
	widget_base_instance_data *data;

	appcore_multiwindow_base_class_on_resume(instance_h);
	id = appcore_multiwindow_base_instance_get_id(instance_h);
	class_id = appcore_multiwindow_base_instance_get_class_id(instance_h);
	cls = __get_class(class_id);
	if (cls == NULL) {
		LOGE("class not found: %s", class_id);
		return;
	}

	data = (widget_base_instance_data *)
			appcore_multiwindow_base_instance_get_extra(instance_h);

	if (data->pending_update) {
		LOGD("pending update!");
		data->pending_update = false;
		__call_update_cb(class_id, data->id, 0, data->pending_content);
		if (data->period > 0) {
			LOGD("Restart timer!");
			data->periodic_timer = g_timeout_add_seconds(
					data->period,
					__timeout_cb, data);
		}
	}

	if (cls->ops.resume)
		cls->ops.resume(instance_h, class_data);

	LOGD("%s is resumed", id);
	__send_update_status(class_id, id,
		WIDGET_INSTANCE_EVENT_RESUME, 0, NULL);

	if (!__fg_signal) {
		LOGD("Send fg signal to resourceD");
		aul_widget_instance_change_status(class_id, STATUS_FOREGROUND);
		__fg_signal = true;
	}
}

static void __multiwindow_instance_pause(
		appcore_multiwindow_base_instance_h instance_h,
		void *class_data)
{
	const char *id;
	const char *class_id;
	widget_base_class *cls;

	appcore_multiwindow_base_class_on_pause(instance_h);
	id = appcore_multiwindow_base_instance_get_id(instance_h);
	class_id = appcore_multiwindow_base_instance_get_class_id(instance_h);
	cls = __get_class(class_id);
	if (cls == NULL) {
		LOGE("class not found: %s", class_id);
		return;
	}

	if (cls->ops.pause)
		cls->ops.pause(instance_h, class_data);

	LOGD("%s is paused", id);
	__send_update_status(class_id, id,
		WIDGET_INSTANCE_EVENT_PAUSE, 0, NULL);

	if (__fg_signal) {
		LOGD("Send bg signal to resourceD");
		aul_widget_instance_change_status(class_id, STATUS_BACKGROUND);
		__fg_signal = false;
	}
}

static void __multiwindow_instance_terminate(
		appcore_multiwindow_base_instance_h instance_h,
		void *class_data)
{
	widget_base_instance_data *data;
	bundle *b;
	char *operation = NULL;
	bundle *content_info;
	widget_base_destroy_type_e reason = WIDGET_BASE_DESTROY_TYPE_TEMPORARY;
	int event = WIDGET_INSTANCE_EVENT_TERMINATE;
	const char *id;
	const char *class_id;
	widget_base_class *cls;

	id = appcore_multiwindow_base_instance_get_id(instance_h);
	class_id = appcore_multiwindow_base_instance_get_class_id(instance_h);
	data  = appcore_multiwindow_base_instance_get_extra(
			(appcore_multiwindow_base_instance_h)instance_h);
	b = data->args;
	cls = __get_class(class_id);
	if (cls == NULL) {
		LOGE("class not found: %s", class_id);
		return;
	}

	if (b) {
		bundle_get_str(b, WIDGET_K_OPERATION, &operation);
		if (operation && strcmp(operation, "destroy") == 0)
			reason = WIDGET_BASE_DESTROY_TYPE_PERMANENT;
	}

	if (data->content)
		content_info = bundle_decode((const bundle_raw *)data->content,
				strlen(data->content));
	else
		content_info = bundle_create();

	if (cls->ops.destroy)
		cls->ops.destroy(instance_h, reason, content_info, class_data);

	LOGW("%s is destroyed %d", id, reason);
	if (reason == WIDGET_BASE_DESTROY_TYPE_PERMANENT) {
		__is_permanent = true;
		event = WIDGET_INSTANCE_EVENT_DESTROY;
		aul_widget_instance_del(class_id, id);
	} else {
		__is_permanent = false;
		__send_update_status(class_id, id,
				WIDGET_INSTANCE_EVENT_EXTRA_UPDATED, 0,
				content_info);
	}

	if (content_info)
		bundle_free(content_info);

	if (data->periodic_timer)
		g_source_remove(data->periodic_timer);

	__send_update_status(class_id, id, event, 0, NULL);
	appcore_multiwindow_base_class_on_terminate(instance_h);
}

EXPORT_API int widget_base_class_on_create(widget_base_instance_h instance_h,
		bundle *content, int w, int h)
{
	appcore_multiwindow_base_class_on_create(instance_h);

	return 0;
}

EXPORT_API int widget_base_class_on_pause(widget_base_instance_h instance_h)
{
	appcore_multiwindow_base_class_on_pause(instance_h);

	return 0;
}

EXPORT_API int widget_base_class_on_resume(widget_base_instance_h instance_h)
{
	appcore_multiwindow_base_class_on_resume(instance_h);

	return 0;
}

EXPORT_API int widget_base_class_on_resize(widget_base_instance_h instance_h,
		int w, int h)
{
	return 0;
}

EXPORT_API int widget_base_class_on_update(widget_base_instance_h instance_h,
		bundle *content, int force)
{
	return 0;
}

EXPORT_API int widget_base_class_on_destroy(widget_base_instance_h instance_h,
		widget_base_destroy_type_e reason, bundle *content)
{
	appcore_multiwindow_base_class_on_terminate(instance_h);

	return 0;
}

EXPORT_API widget_base_class widget_base_class_get_default(void)
{
	widget_base_class cls;

	cls.ops.create = __class_on_create;
	cls.ops.resize = __class_on_resize;
	cls.ops.update = __class_on_update;
	cls.ops.destroy = __class_on_destroy;
	cls.ops.pause = __class_on_pause;
	cls.ops.resume = __class_on_resume;
	cls.id = NULL;

	return cls;
}

EXPORT_API widget_base_class *widget_base_class_add(widget_base_class cls,
		const char *class_id, void *class_data)
{
	widget_base_class *c;
	appcore_multiwindow_base_class raw_cls;

	if (!__is_widget_feature_enabled()) {
		LOGE("not supported");
		set_last_result(WIDGET_ERROR_NOT_SUPPORTED);
		return NULL;
	}

	if (!class_id) {
		LOGE("class is is NULL");
		set_last_result(WIDGET_ERROR_INVALID_PARAMETER);
		return NULL;
	}

	raw_cls.id = strdup(class_id);
	raw_cls.data = class_data;
	raw_cls.create = __multiwindow_instance_create;
	raw_cls.terminate = __multiwindow_instance_terminate;
	raw_cls.pause = __multiwindow_instance_pause;
	raw_cls.resume = __multiwindow_instance_resume;
	appcore_multiwindow_base_class_add(raw_cls);

	c = malloc(sizeof(widget_base_class));
	if (!c)
		return NULL;

	*c = cls;
	c->id = strdup(class_id);
	__context.classes = g_list_append(__context.classes, c);

	return c;
}
