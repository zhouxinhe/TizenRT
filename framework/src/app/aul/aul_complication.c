/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd All Rights Reserved
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

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <bundle_internal.h>

#include "aul_api.h"
#include "aul_util.h"
#include "aul_sock.h"
#include "aul_complication.h"
#include "aul.h"

#define MAX_UID_STR_BUFSZ 20

API int aul_complication_update_request(const char *appid, const char *provider_appid, uid_t uid)
{
	bundle *b;
	int r;
	char buf[MAX_UID_STR_BUFSZ];

	if (!appid || !provider_appid) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	b = bundle_create();
	if (!b) {
		_E("Out of memory");
		return AUL_R_ERROR;
	}

	r = bundle_add(b, AUL_K_CALLER_APPID, appid);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add appid(%s)", appid);
		bundle_free(b);
		return AUL_R_ERROR;
	}

	r = bundle_add(b, AUL_K_APPID, provider_appid);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add provider_appid(%s)", provider_appid);
		bundle_free(b);
		return AUL_R_ERROR;
	}

	r = bundle_add(b, AUL_K_COMPLICATION_MODE, UPDATE_REQUEST);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add appid(%s)", appid);
		bundle_free(b);
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%d", uid);
	r = bundle_add(b, AUL_K_TARGET_UID, buf);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add uid(%d)", uid);
		bundle_free(b);
		return AUL_R_ERROR;
	}

	r = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
		COMPLICATION_UPDATE_REQUEST, b, AUL_SOCK_QUEUE);
	if (r < 0) {
		_E("Failed to send request(%d:%s)",
				COMPLICATION_UPDATE_REQUEST, appid);
		bundle_free(b);
		return r;
	}
	bundle_free(b);

	return AUL_R_OK;
}

API int aul_complication_launch_with_extra_data(const char *appid,
		const char *provider_appid, uid_t uid, const char *key, char *value)
{
	bundle *b;
	int r;
	char buf[MAX_UID_STR_BUFSZ];

	if (!appid || !provider_appid || !key || !value) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	b = bundle_create();
	if (!b) {
		_E("Out of memory");
		return AUL_R_ERROR;
	}

	r = bundle_add(b, AUL_K_CALLER_APPID, appid);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add appid(%s)", appid);
		bundle_free(b);
		return AUL_R_ERROR;
	}

	r = bundle_add(b, AUL_K_APPID, provider_appid);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add provider_appid(%s)", provider_appid);
		bundle_free(b);
		return AUL_R_ERROR;
	}

	r = bundle_add(b, AUL_K_COMPLICATION_MODE, LAUNCH_REQUEST);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add appid(%s)", appid);
		bundle_free(b);
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%d", uid);
	r = bundle_add(b, AUL_K_TARGET_UID, buf);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add uid(%d)", uid);
		bundle_free(b);
		return AUL_R_ERROR;
	}

	if (key && value) {
		r = bundle_add(b, key, value);
		if (r != BUNDLE_ERROR_NONE) {
			_E("Failed to add key value data (%s)", key);
			bundle_free(b);
			return AUL_R_ERROR;
		}
	}

	r = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
		COMPLICATION_UPDATE_REQUEST, b, AUL_SOCK_QUEUE);
	if (r < 0) {
		_E("Failed to send request(%d:%s)",
				COMPLICATION_UPDATE_REQUEST, appid);
		bundle_free(b);
		return r;
	}
	bundle_free(b);

	return AUL_R_OK;
}
