/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
 *
 */

#define _GNU_SOURCE
#include <glib.h>
#include "aul.h"
#include "launch.h"
#include "aul_cmd.h"
#include "aul_util.h"
#include "aul_api.h"
#include "aul_app_com.h"

static GList *handlers = NULL;

struct _aul_app_com_connection_s {
	char *endpoint;
	app_com_cb callback;
	void *user_data;
};

struct _aul_app_com_permission_s {
	char *privilege;
	unsigned int propagation;
};

int app_com_recv(bundle *b)
{
	int ret = 0;
	char *endpoint = NULL;
	size_t result_sz;
	int *result;
	GList *head = handlers;
	aul_app_com_connection_s *handler = NULL;

	if (b == NULL)
		return -1;

	ret = bundle_get_str(b, AUL_K_COM_ENDPOINT, &endpoint);
	if (ret != BUNDLE_ERROR_NONE)
		return -1;

	ret = bundle_get_byte(b, AUL_K_COM_RESULT, (void **)&result, &result_sz);
	if (ret != BUNDLE_ERROR_NONE)
		return -1;

	while (head) {
		handler = (aul_app_com_connection_s *)head->data;
		if (handler && handler->endpoint && g_strcmp0(handler->endpoint, endpoint) == 0)
			handler->callback(endpoint, *result, b, handler->user_data);

		head = head->next;
	}

	return 0;
}

API aul_app_com_permission_h aul_app_com_permission_create()
{
	aul_app_com_permission_s *p = NULL;
	p = (aul_app_com_permission_s *)g_malloc0(sizeof(aul_app_com_permission_s));

	return p;
}

API void aul_app_com_permission_destroy(aul_app_com_permission_h permission)
{
	if (permission == NULL)
		return;

	if (permission->privilege)
		g_free(permission->privilege);
	g_free(permission);
}

API int aul_app_com_permission_set_propagation(aul_app_com_permission_h permission, aul_app_com_propagate_option_e option)
{
	if (permission)
		permission->propagation = option;

	return 0;
}

API int aul_app_com_permission_set_privilege(aul_app_com_permission_h permission, const char *privilege)
{
	if (permission) {
		if (permission->privilege)
			g_free(permission->privilege);

		permission->privilege = g_strdup(privilege);
	}

	return 0;
}

static aul_app_com_connection_h __add_handler(const char *endpoint, app_com_cb callback, void *user_data)
{
	aul_app_com_connection_s *h = NULL;
	h = (aul_app_com_connection_s *)g_malloc0(sizeof(aul_app_com_connection_s));
	if (h == NULL) {
		_E("out of memory");
		return NULL;
	}

	h->callback = callback;
	h->user_data = user_data;
	h->endpoint = g_strdup(endpoint);

	handlers = g_list_append(handlers, h);

	return h;
}

API int aul_app_com_create(const char *endpoint, aul_app_com_permission_h permission, app_com_cb callback, void *user_data, aul_app_com_connection_h *connection)
{
	bundle *b = NULL;
	int ret = 0;

	if (endpoint == NULL || callback == NULL || connection == NULL)
		return -1;

	b = bundle_create();

	if (!b) {
		_E("out of memory");
		return -1;
	}

	bundle_add_str(b, AUL_K_COM_ENDPOINT, endpoint);

	if (permission) {
		if (permission->propagation)
			bundle_add_byte(b, AUL_K_COM_PROPAGATE,
				(void *)(GUINT_TO_POINTER(permission->propagation)), sizeof(unsigned int));

		if (permission->privilege)
			bundle_add_str(b, AUL_K_COM_PRIVILEGE, permission->privilege);
	}

	ret = app_send_cmd(AUL_UTIL_PID, APP_COM_CREATE, b);
	bundle_free(b);

	if (ret == 0)
		*connection = __add_handler(endpoint, callback, user_data);

	return ret;
}

API int aul_app_com_join(const char *endpoint, const char *filter, app_com_cb callback, void *user_data, aul_app_com_connection_h *connection)
{
	bundle *b = NULL;
	int ret = 0;

	if (endpoint == NULL || callback == NULL || connection == NULL)
		return -1;

	b = bundle_create();

	if (!b) {
		_E("out of memory");
		return -1;
	}

	bundle_add_str(b, AUL_K_COM_ENDPOINT, endpoint);
	if (filter)
		bundle_add_str(b, AUL_K_COM_FILTER, filter);

	ret = app_send_cmd(AUL_UTIL_PID, APP_COM_JOIN, b);
	bundle_free(b);

	if (ret == 0)
		*connection = __add_handler(endpoint, callback, user_data);

	return ret;
}

API int aul_app_com_send(const char *endpoint, bundle *envelope)
{
	int ret = 0;

	if (endpoint == NULL || envelope == NULL)
		return -1;

	bundle_add_str(envelope, AUL_K_COM_ENDPOINT, endpoint);

	ret = app_send_cmd(AUL_UTIL_PID, APP_COM_SEND, envelope);

	return ret;
}

API int aul_app_com_leave(aul_app_com_connection_h connection)
{
	bundle *b = NULL;
	int ret = 0;
	GList *head = handlers;
	aul_app_com_connection_s *h = NULL;
	int endpoint_cnt = 0;

	if (connection == NULL)
		return -1;

	while (head) {
		h = (aul_app_com_connection_s *)head->data;
		head = head->next;
		if (h && h->endpoint && g_strcmp0(h->endpoint, connection->endpoint) == 0) {
			if (h == connection)
				handlers = g_list_remove(handlers, h);
			else
				endpoint_cnt++;
		}
	}

	if (endpoint_cnt > 0) {
		g_free(connection->endpoint);
		g_free(connection);
		return 0;
	}

	b = bundle_create();
	if (!b) {
		_E("out of memory");
		return -1;
	}

	bundle_add_str(b, AUL_K_COM_ENDPOINT, connection->endpoint);

	ret = app_send_cmd(AUL_UTIL_PID, APP_COM_LEAVE, b);

	bundle_free(b);
	g_free(connection->endpoint);
	g_free(connection);

	return ret;
}
