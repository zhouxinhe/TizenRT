/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <glib.h>
#include <bundle.h>
#include <bundle_internal.h>

#include "aul_util.h"
#include "aul_api.h"
#include "aul.h"
#include "aul_sock.h"
#include "aul_app_com.h"
#include "aul_screen_connector.h"

struct aul_screen_viewer_s {
	aul_app_com_connection_h conn;
	aul_screen_viewer_cb callback;
	aul_screen_type_e type;
	bool priv;
	unsigned int ref;
	void *user_data;
};

static unsigned int ref;

static unsigned int __get_ref(void)
{
	return ++ref;
}

static int __add_screen_viewer(int type, bool priv, unsigned int ref)
{
	int ret;
	bundle *b;
	char buf[MAX_PID_STR_BUFSZ];

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return -1;
	}

	snprintf(buf, sizeof(buf), "%d", type);
	ret = bundle_add(b, AUL_K_SCREEN_TYPE, buf);
	if (ret != BUNDLE_ERROR_NONE) {
		_E("Failed to add screen type(%d)", type);
		bundle_free(b);
		return -1;
	}

	snprintf(buf, sizeof(buf), "%u", ref);
	ret = bundle_add(b, AUL_K_VIEWER_REF, buf);
	if (ret != BUNDLE_ERROR_NONE) {
		_E("Failed to add viewer reference(%u)", ref);
		bundle_free(b);
		return -1;
	}

	if (priv) {
		ret = bundle_add(b, AUL_K_PRIVATE, "true");
		if (ret != BUNDLE_ERROR_NONE) {
			_E("Failed to add bundle data");
			bundle_free(b);
			return -1;
		}
	}

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			ADD_SCREEN_VIEWER, b, AUL_SOCK_NOREPLY);
	bundle_free(b);
	if (ret < 0)
		return -1;

	return 0;
}

static int __remove_screen_viewer(int type, bool priv, unsigned int ref)
{
	int ret;
	bundle *b;
	char buf[MAX_PID_STR_BUFSZ];

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return -1;
	}

	snprintf(buf, sizeof(buf), "%d", type);
	ret = bundle_add(b, AUL_K_SCREEN_TYPE, buf);
	if (ret != BUNDLE_ERROR_NONE) {
		_E("Failed to add view mode");
		bundle_free(b);
		return -1;
	}

	snprintf(buf, sizeof(buf), "%u", ref);
	ret = bundle_add(b, AUL_K_VIEWER_REF, buf);
	if (ret != BUNDLE_ERROR_NONE) {
		_E("Failed to add viewer reference(%u)", ref);
		bundle_free(b);
		return -1;
	}

	if (priv) {
		ret = bundle_add(b, AUL_K_PRIVATE, "true");
		if (ret != BUNDLE_ERROR_NONE) {
			_E("Failed to add bundle data");
			bundle_free(b);
			return -1;
		}
	}

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			REMOVE_SCREEN_VIEWER, b, AUL_SOCK_NOREPLY);
	bundle_free(b);
	if (ret < 0)
		return -1;

	return 0;
}

static int __app_screen_event_cb(const char *endpoint, aul_app_com_result_e res,
		bundle *envelope, void *user_data)
{
	aul_screen_viewer_h handle = (aul_screen_viewer_h)user_data;
	char *appid = NULL;
	char *instance_id = NULL;
	unsigned int *surf = NULL;
	int *pid = NULL;
	size_t size;
	char *event = NULL;
	aul_screen_connector_event_type_e event_type;

	bundle_get_str(envelope, "__AUL_SC_EVENT__", &event);
	if (event == NULL) {
		_E("Failed to get screen connector event");
		return -1;
	} else if (strcmp(event, "add_screen") == 0) {
		event_type = AUL_SCREEN_CONNECTOR_EVENT_TYPE_ADD;
	} else if (strcmp(event, "remove_screen") == 0) {
		event_type = AUL_SCREEN_CONNECTOR_EVENT_TYPE_REMOVE;
	} else if (strcmp(event, "update_screen") == 0) {
		event_type = AUL_SCREEN_CONNECTOR_EVENT_TYPE_UPDATE;
	} else {
		_E("Unknown event type(%s)", event);
		return -1;
	}

	bundle_get_str(envelope, "__AUL_SC_APPID__", &appid);
	if (appid == NULL) {
		_E("Failed to get appid");
		return -1;
	}

	bundle_get_byte(envelope, "__AUL_SC_SURFACE__",
			(void **)&surf, &size);
	if (surf == NULL) {
		_E("Failed to get surface");
		return -1;
	}

	bundle_get_byte(envelope, "__AUL_SC_PID__", (void **)&pid, &size);
	if (pid == NULL) {
		_E("Failed to get pid");
		return -1;
	}
	bundle_get_str(envelope, "__AUL_SC_INSTANCE_ID__", &instance_id);

	if (handle->callback) {
		handle->callback(appid, instance_id, *pid, *surf,
				event_type, handle->user_data);
	}
	_D("appid(%s), instance_id(%s), pid(%d), surface(%d), event_type(%d)",
			appid, instance_id, *pid, *surf, event_type);

	return 0;
}

static int __screen_viewer_fini(aul_screen_viewer_h screen_viewer)
{
	int ret;

	if (screen_viewer->conn) {
		aul_app_com_leave(screen_viewer->conn);
		screen_viewer->conn = NULL;
	}

	ret = __remove_screen_viewer(screen_viewer->type, screen_viewer->priv,
			screen_viewer->ref);
	if (ret < 0) {
		_E("Failed to remove screen watcher");
		return -1;
	}

	return 0;
}

static int __screen_viewer_init(aul_screen_viewer_h screen_viewer)
{
	int ret;
	char endpoint[128];
	pid_t pid = getpid();

	snprintf(endpoint, sizeof(endpoint), "app_screen_event:%u:%d",
			screen_viewer->ref, pid);
	aul_app_com_create(endpoint, NULL, __app_screen_event_cb,
			screen_viewer, &screen_viewer->conn);
	if (screen_viewer->conn == NULL) {
		_E("Failed to create app com");
		return -1;
	}

	ret = __add_screen_viewer(screen_viewer->type, screen_viewer->priv,
			screen_viewer->ref);
	if (ret < 0) {
		_E("Failed to add screen watcher");
		return -1;
	}

	return 0;
}

API int aul_screen_connector_add_screen_viewer(aul_screen_viewer_cb callback,
		aul_screen_type_e type, bool priv,
		void *data, aul_screen_viewer_h *handle)
{
	struct aul_screen_viewer_s *screen_viewer;

	if (handle == NULL || callback == NULL ||
			!(type & AUL_SCREEN_TYPE_ALL)) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	screen_viewer = (struct aul_screen_viewer_s *)calloc(1,
			sizeof(struct aul_screen_viewer_s));
	if (screen_viewer == NULL) {
		_E("Out of memory");
		return AUL_R_EINVAL;
	}

	screen_viewer->callback = callback;
	screen_viewer->type = type;
	screen_viewer->priv = priv;
	screen_viewer->ref = __get_ref();
	screen_viewer->user_data = data;

	if (__screen_viewer_init(screen_viewer) < 0) {
		__screen_viewer_fini(screen_viewer);
		free(screen_viewer);
		return AUL_R_ERROR;
	}
	*handle = screen_viewer;

	return AUL_R_OK;
}

API int aul_screen_connector_remove_screen_viewer(aul_screen_viewer_h handle)
{
	if (handle == NULL)
		return AUL_R_EINVAL;

	__screen_viewer_fini(handle);
	free(handle);

	return AUL_R_OK;
}

API int aul_screen_connector_add_app_screen(const char *instance_id,
		unsigned int surf)
{
	int ret;
	bundle *b;
	char buf[MAX_PID_STR_BUFSZ];

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%d", surf);
	ret = bundle_add(b, AUL_K_WID, buf);
	if (ret != BUNDLE_ERROR_NONE) {
		_E("Failed to add surf");
		bundle_free(b);
		return AUL_R_ERROR;
	}

	if (instance_id) {
		ret = bundle_add(b, AUL_K_INSTANCE_ID, instance_id);
		if (ret != BUNDLE_ERROR_NONE) {
			_E("Failed to add instance id");
			bundle_free(b);
			return AUL_R_ERROR;
		}
	}

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			ADD_APP_SCREEN, b, AUL_SOCK_NOREPLY);
	bundle_free(b);
	if (ret < 0) {
		_E("Failed to add app screen");
		return ret;
	}

	return AUL_R_OK;
}

API int aul_screen_connector_remove_app_screen(const char *instance_id)
{
	int ret;
	bundle *b;

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	if (instance_id) {
		ret = bundle_add(b, AUL_K_INSTANCE_ID, instance_id);
		if (ret != BUNDLE_ERROR_NONE) {
			_E("Failed to add instance id");
			bundle_free(b);
			return AUL_R_ERROR;
		}
	}

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			REMOVE_APP_SCREEN, b, AUL_SOCK_NOREPLY);
	bundle_free(b);
	if (ret < 0) {
		_E("Failed to remove app screen");
		return ret;
	}

	return AUL_R_OK;
}

API int aul_screen_connector_send_update_request(const char *appid,
		const char *instance_id)
{
	int ret;
	bundle *b;

	if (appid == NULL) {
		_E("Invalid parameter");
		return -1;
	}

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	ret = bundle_add(b, AUL_K_APPID, appid);
	if (ret != BUNDLE_ERROR_NONE) {
		_E("Failed to add appid");
		bundle_free(b);
		return AUL_R_ERROR;
	}

	if (instance_id) {
		ret = bundle_add(b, AUL_K_INSTANCE_ID, instance_id);
		if (ret != BUNDLE_ERROR_NONE) {
			_E("Failed to add instance id");
			bundle_free(b);
			return AUL_R_ERROR;
		}
	}

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			APP_UPDATE_REQUESTED, b, AUL_SOCK_NOREPLY);
	bundle_free(b);
	if (ret < 0) {
		_E("Failed to update app screen");
		return ret;
	}

	return AUL_R_OK;
}

static bundle *__send_request_with_surface_id(int cmd, unsigned int surface_id)
{
	app_pkt_t *pkt = NULL;
	bundle *b;
	int fd;
	int r;

	b = bundle_create();
	if (b == NULL) {
		_E("Out of memory");
		return NULL;
	}

	r = bundle_add_byte(b, "__AUL_SC_SURFACE__",
			&surface_id, sizeof(unsigned int));
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add surface id(%u)", surface_id);
		bundle_free(b);
		return NULL;
	}

	fd = aul_sock_send_bundle(AUL_UTIL_PID, getuid(), cmd, b,
			AUL_SOCK_ASYNC);
	bundle_free(b);
	if (fd < 0) {
		_E("Failed to send request(%d)", cmd);
		return NULL;
	}

	aul_sock_recv_reply_pkt(fd, &pkt);
	if (pkt == NULL) {
		_E("Failed to receive the packet");
		return NULL;
	}

	b = bundle_decode(pkt->data, pkt->len);
	free(pkt);
	if (b == NULL) {
		_E("Failed to decode bundle data");
		return NULL;
	}

	return b;
}

API int aul_screen_connector_get_appid_by_surface_id(unsigned int surface_id,
		char **appid)
{
	const char *val;
	bundle *b;

	if (appid == NULL) {
		_E("Invalid parameter");
		return AUL_R_ERROR;
	}

	b = __send_request_with_surface_id(APP_GET_APPID_BY_SURFACE_ID,
			surface_id);
	if (b == NULL)
		return AUL_R_ERROR;

	val = bundle_get_val(b, AUL_K_APPID);
	if (val == NULL) {
		_E("Failed to get appid");
		bundle_free(b);
		return AUL_R_ERROR;
	}

	*appid = strdup(val);
	if (*appid == NULL) {
		_E("Out of memory");
		bundle_free(b);
		return AUL_R_ERROR;
	}
	bundle_free(b);

	return AUL_R_OK;
}

API int aul_screen_connector_get_instance_id_by_surface_id(
		unsigned int surface_id, char **instance_id)
{
	const char *val;
	bundle *b;

	if (instance_id == NULL) {
		_E("Invalid parameter");
		return AUL_R_ERROR;
	}

	b = __send_request_with_surface_id(APP_GET_INSTANCE_ID_BY_SURFACE_ID,
			surface_id);
	if (b == NULL)
		return AUL_R_ERROR;

	val = bundle_get_val(b, AUL_K_INSTANCE_ID);
	if (val == NULL) {
		_E("Failed to get instance id");
		bundle_free(b);
		return AUL_R_ERROR;
	}

	*instance_id = strdup(val);
	if (*instance_id == NULL) {
		_E("Out of memory");
		bundle_free(b);
		return AUL_R_ERROR;
	}
	bundle_free(b);

	return AUL_R_OK;
}


API int aul_screen_connector_update_screen_viewer_status(
		aul_screen_status_e status, unsigned int provider_surf)
{
	char buf[32];
	bundle *b;
	int ret;

	if (status < AUL_SCREEN_STATUS_RESUME ||
			status > AUL_SCREEN_STATUS_PAUSE) {
		_E("Invalid parameter");
		return AUL_R_ERROR;
	}

	b = bundle_create();
	if (b == NULL) {
		_E("Out of memory");
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%u", provider_surf);
	ret = bundle_add(b, AUL_K_WID, buf);
	if (ret != BUNDLE_ERROR_NONE) {
		_E("Failed to add provider surface id");
		bundle_free(b);
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%d", status);
	ret = bundle_add(b, "__AUL_SC_VIEWER_STATUS__", buf);
	if (ret != BUNDLE_ERROR_NONE) {
		_E("Failed to add screen status");
		bundle_free(b);
		return AUL_R_ERROR;
	}

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			UPDATE_SCREEN_VIEWER_STATUS, b, AUL_SOCK_NOREPLY);
	bundle_free(b);

	return ret;
}
