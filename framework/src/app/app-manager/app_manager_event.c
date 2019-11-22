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

#include <stdlib.h>
#include <sys/types.h>

#include <dlog.h>
#include <package-manager.h>

#include "app_manager_internal.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "CAPI_APPFW_APP_MANAGER"

static int __remove_app_manager_event_info(app_manager_event_info **head, int req_id)
{
	app_manager_event_info *prev;
	app_manager_event_info *current;

	current = prev = *head;
	if (current == NULL)
		return APP_MANAGER_ERROR_INVALID_PARAMETER;

	while (current) {
		if (current->req_id == req_id) {
			if (prev == current)
				*head = current->next;
			prev->next = current->next;
			free(current);
			return APP_MANAGER_ERROR_NONE;
		}
		prev = current;
		current = current->next;
	}

	return APP_MANAGER_ERROR_NONE;
}

static int __find_app_manager_event_info(app_manager_event_info **head,
		int req_id, app_manager_event_type_e *event_type)
{
	app_manager_event_info *tmp;

	tmp = *head;

	if (tmp == NULL) {
		LOGE("head is null");
		return APP_MANAGER_ERROR_INVALID_PARAMETER;
	}

	while (tmp) {
		if (tmp->req_id == req_id) {
			*event_type = tmp->event_type;
			return APP_MANAGER_ERROR_NONE;
		}
		tmp = tmp->next;
	}

	return APP_MANAGER_ERROR_REQUEST_FAILED;
}

static int __add_app_manager_event_info(app_manager_event_info **head,
		int req_id, app_manager_event_type_e event_type)
{
	app_manager_event_info *event_info;
	app_manager_event_info *current;
	app_manager_event_info *prev;

	event_info = (app_manager_event_info *)calloc(1, sizeof(app_manager_event_info));
	if (event_info == NULL)
		return APP_MANAGER_ERROR_OUT_OF_MEMORY;

	event_info->req_id = req_id;
	event_info->event_type = event_type;
	event_info->next = NULL;

	if (*head == NULL) {
		*head = event_info;
	} else {
		current = prev = *head;
		while (current) {
			prev = current;
			current = current->next;
		}
		prev->next = event_info;
	}

	return APP_MANAGER_ERROR_NONE;
}

static int __get_app_manager_event_type(const char *key, app_manager_event_type_e *event_type)
{
	if (key == NULL)
		return APP_MANAGER_ERROR_INVALID_PARAMETER;

	if (strcasecmp(key, "disable_app") == 0 ||
			strcasecmp(key, "disable_global_app_for_uid") == 0)
		*event_type = APP_MANAGER_EVENT_DISABLE_APP;
	else if (strcasecmp(key, "enable_app") == 0 ||
			strcasecmp(key, "enable_global_app_for_uid") == 0)
		*event_type = APP_MANAGER_EVENT_ENABLE_APP;
	else
		return APP_MANAGER_ERROR_INVALID_PARAMETER;
	return APP_MANAGER_ERROR_NONE;
}

void remove_app_manager_event_info_list(app_manager_event_info *head)
{
	if (head == NULL)
		return;

	app_manager_event_info *current = head;

	if (current->next != NULL)
		remove_app_manager_event_info_list(current->next);

	free(current);
	return;
}

int app_event_handler(uid_t target_uid, int req_id,
				const char *pkg_type, const char *pkgid, const char *appid,
				const char *key, const char *val, const void *pmsg, void *data)
{
	app_manager_event *app_evt = (app_manager_event *)data;
	app_manager_event_type_e event_type = -1;
	int ret = -1;

	LOGI("app_event_handler called");

	if (app_evt == NULL || app_evt->event_cb == NULL)
		return APP_MANAGER_ERROR_INVALID_PARAMETER;

	if (strcasecmp(key, "start") == 0) {
		ret = __get_app_manager_event_type(val, &event_type);
		if (ret != APP_MANAGER_ERROR_NONE)
			return APP_MANAGER_ERROR_INVALID_PARAMETER;

		ret = __add_app_manager_event_info(&(app_evt->head), req_id, event_type);
		if (ret != APP_MANAGER_ERROR_NONE)
			return APP_MANAGER_ERROR_REQUEST_FAILED;

		app_evt->event_cb(pkg_type, appid, event_type,
				APP_MANAGER_EVENT_STATE_STARTED, app_evt, app_evt->user_data);
	} else if (strcasecmp(key, "end") == 0) {
		if (__find_app_manager_event_info(&(app_evt->head), req_id, &event_type)
				!= APP_MANAGER_ERROR_NONE)
			return APP_MANAGER_ERROR_REQUEST_FAILED;

		if (strcasecmp(val, "ok") == 0) {
			app_evt->event_cb(pkg_type, appid, event_type,
					APP_MANAGER_EVENT_STATE_COMPLETED, app_evt, app_evt->user_data);
		} else if (strcasecmp(val, "fail") == 0) {
			/* LCOV_EXCL_START */
			app_evt->event_cb(pkg_type, appid, event_type,
					APP_MANAGER_EVENT_STATE_FAILED, app_evt, app_evt->user_data);
			/* LCOV_EXCL_STOP */
		}

		ret = __remove_app_manager_event_info(&(app_evt->head), req_id);
		if (ret != APP_MANAGER_ERROR_NONE) {
			/* LCOV_EXCL_START */
			LOGE("failed to remove app event info");
			return APP_MANAGER_ERROR_REQUEST_FAILED;
			/* LCOV_EXCL_STOP */
		}

	} else {
		return APP_MANAGER_ERROR_INVALID_PARAMETER;
	}

	return APP_MANAGER_ERROR_NONE;
}

int convert_status_type(int status_type)
{
	int result = 0;

	if (status_type == 0)
		return PKGMGR_CLIENT_STATUS_ALL;

	if ((status_type & APP_MANAGER_EVENT_STATUS_TYPE_ENABLE)
			== APP_MANAGER_EVENT_STATUS_TYPE_ENABLE)
		result += PKGMGR_CLIENT_STATUS_ENABLE_APP;

	if ((status_type & APP_MANAGER_EVENT_STATUS_TYPE_DISABLE)
			== APP_MANAGER_EVENT_STATUS_TYPE_DISABLE)
		result += PKGMGR_CLIENT_STATUS_DISABLE_APP;

	return result;
}

