/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <tizen.h>
#include <dlog.h>
#include <app_event.h>
#include <eventsystem.h>

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "CAPI_APPFW_EVENT"

typedef struct event_handler {
	char *event_name;
	int event_type;
	unsigned int reg_id;
	event_cb cb;
	void *user_data;
} event_handler_s;

typedef struct event_cb_data {
	bundle *event_data;
	void *user_data;
} event_cb_data_s;

static GHashTable *interested_event_table;
static int _initialized;
static event_cb earlier_callback;
static pthread_mutex_t register_sync_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *event_error_to_string(event_error_e error)
{
	switch (error) {
	case EVENT_ERROR_NONE:
		return "NONE";
	case EVENT_ERROR_INVALID_PARAMETER:
		return "INVALID_PARAMETER";
	case EVENT_ERROR_OUT_OF_MEMORY:
		return "OUT_OF_MEMORY";
	case EVENT_ERROR_TIMED_OUT:
		return "TIMED_OUT";
	case EVENT_ERROR_IO_ERROR:
		return "IO ERROR";
	case EVENT_ERROR_PERMISSION_DENIED:
		return "PERMISSION DENIED";
	default:
		return "UNKNOWN";
	}
}

int event_error(event_error_e error, const char *function, const char *description)
{
	if (description) {
		LOGE("[%s] %s(0x%08x) : %s", function, event_error_to_string(error),
			error, description);
	} else {
		LOGE("[%s] %s(0x%08x)", function, event_error_to_string(error), error);
	}

	return error;
}

static void event_do_cb(gpointer data, gpointer user_data)
{
	event_handler_h handler = (event_handler_h)data;
	event_cb_data_s *cb_data = (event_cb_data_s *)user_data;

	if (handler->cb) {
		handler->cb(handler->event_name,
			cb_data->event_data, cb_data->user_data);
	}
}

static void event_eventsystem_callback(const char *event_name,
	bundle_raw *event_data, int len, void *user_data)
{
	bundle *b_to = NULL;
	bundle *b = NULL;

	LOGD("event_name(%s)", event_name);

	if (earlier_callback != NULL) {
		b_to = bundle_decode(event_data, len);
		if (b_to == NULL) {
			LOGE("bundle_decode failed");
			return;
		}
		earlier_callback(event_name, b_to, user_data);
		bundle_free(b_to);
		return;
	}

	GList *handler_list = (GList *)g_hash_table_lookup(interested_event_table,
		event_name);
	if (handler_list) {
		event_cb_data_s *cb_data = NULL;
		cb_data = calloc(1, sizeof(event_cb_data_s));
		if (cb_data == NULL) {
			LOGE("memory alloc failed");
			return;
		}
		b_to = bundle_decode(event_data, len);
		if (b_to == NULL) {
			LOGE("bundle_decode failed");
			free(cb_data);
			return;
		}
		b = bundle_dup(b_to);
		bundle_free(b_to);

		cb_data->event_data = b;
		cb_data->user_data = user_data;

		g_list_foreach(handler_list, event_do_cb, cb_data);

		bundle_free(b);
	}
}

int event_add_event_handler(const char *event_name, event_cb callback, void *user_data,
	event_handler_h *event_handler)
{
	int ret = 0;
	int event_type = 0;
	unsigned int reg_id = 0;
	event_handler_h handler = NULL;

	if (!_initialized) {
		if (interested_event_table == NULL) {
			interested_event_table = g_hash_table_new(g_str_hash, g_str_equal);
			if (interested_event_table == NULL) {
				return event_error(EVENT_ERROR_OUT_OF_MEMORY,
					__FUNCTION__, NULL);
			}
		}
		_initialized = 1;
	}

	if (event_handler == NULL || event_name == NULL || callback == NULL)
		return event_error(EVENT_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	handler = calloc(1, sizeof(event_handler_s));
	if (handler == NULL)
		return event_error(EVENT_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);

	pthread_mutex_lock(&register_sync_lock);
	earlier_callback = callback;
	ret = eventsystem_register_application_event(event_name, &reg_id, &event_type,
		(eventsystem_cb)event_eventsystem_callback, user_data);
	earlier_callback = NULL;
	pthread_mutex_unlock(&register_sync_lock);
	if (ret < 0) {
		free(handler);
		if (ret == ES_R_ENOTPERMITTED)
			return event_error(EVENT_ERROR_PERMISSION_DENIED, __FUNCTION__, NULL);
		else
			return event_error(EVENT_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	handler->event_name = strdup(event_name);
	if (handler->event_name == NULL) {
		free(handler);
		return event_error(EVENT_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
	}

	handler->reg_id = reg_id;
	handler->event_type = event_type;
	handler->cb = callback;
	handler->user_data = user_data;

	*event_handler = handler;

	GList *handler_list = (GList *)g_hash_table_lookup(interested_event_table,
		handler->event_name);
	if (handler_list) {
		LOGD("add new handler");
		handler_list = g_list_append(handler_list, handler);
	} else {
		LOGD("add new table item");
		GList *ehl = NULL;
		ehl = g_list_append(ehl, handler);
		g_hash_table_insert(interested_event_table, handler->event_name, ehl);
	}

	return EVENT_ERROR_NONE;
}

int event_remove_event_handler(event_handler_h event_handler)
{
	int ret = 0;

	if (!_initialized) {
		LOGI("handler list is not initialized");
		return EVENT_ERROR_NONE;
	}

	if (event_handler == NULL)
		return event_error(EVENT_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	ret = eventsystem_unregister_application_event(event_handler->reg_id);
	if (ret < 0)
		return event_error(EVENT_ERROR_IO_ERROR, __FUNCTION__, NULL);

	GList *handler_list = (GList *)g_hash_table_lookup(interested_event_table,
		event_handler->event_name);
	if (handler_list) {
		GList *list = NULL;
		list = g_list_find(handler_list, event_handler);
		if (list) {
			LOGD("remove match handler");
			handler_list = g_list_remove_all(handler_list, event_handler);
			GList *first_list = NULL;
			first_list = g_list_first(handler_list);
			if (first_list == NULL) {
				LOGD("remove table item");
				g_hash_table_remove(interested_event_table,
					event_handler->event_name);
			}
		}
	}

	free(event_handler->event_name);
	free(event_handler);

	return EVENT_ERROR_NONE;
}

int event_publish_app_event(const char *event_name, bundle *event_data)
{
	if (event_data == NULL || event_name == NULL)
		return event_error(EVENT_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (eventsystem_send_user_event(event_name, event_data, false) < 0)
		return event_error(EVENT_ERROR_IO_ERROR, __FUNCTION__, NULL);

	return EVENT_ERROR_NONE;
}

int event_publish_trusted_app_event(const char *event_name, bundle *event_data)
{
	if (event_data == NULL || event_name == NULL)
		return event_error(EVENT_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (eventsystem_send_user_event(event_name, event_data, true) < 0)
		return event_error(EVENT_ERROR_IO_ERROR, __FUNCTION__, NULL);

	return EVENT_ERROR_NONE;
}

int event_keep_last_event_data(const char *event_name)
{
	int ret;

	if (event_name == NULL)
		return event_error(EVENT_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	ret = eventsystem_keep_last_event_data(event_name);
	if (ret < 0) {
		if (ret == ES_R_ENOMEM)
			return event_error(EVENT_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
		else
			return event_error(EVENT_ERROR_IO_ERROR, __FUNCTION__, NULL);
	}

	return EVENT_ERROR_NONE;
}
