/*
 *  aul
 *
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

#ifndef __APP_COM_H__
#define __APP_COM_H__

#include <app/bundle.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	AUL_APP_COM_PUBLIC = 0x0, /* allowed for all */
	AUL_APP_COM_PRIVILEGED = 0x1, /* allowed for given privileged app */
} aul_app_com_propagate_option_e;

typedef enum {
	AUL_APP_COM_R_ERROR_OK = 0,
	AUL_APP_COM_R_ERROR_UNKNOWN_ENDPOINT = -1,
	AUL_APP_COM_R_ERROR_ENDPOINT_ALREADY_EXISTS = -2,
	AUL_APP_COM_R_ERROR_ILLEGAL_ACCESS = -3,
	AUL_APP_COM_R_ERROR_CLIENT_REMAINING = -4,
	AUL_APP_COM_R_ERROR_OUT_OF_MEMORY = -5,
	AUL_APP_COM_R_ERROR_FATAL_ERROR = -6,
} aul_app_com_error_e;

typedef enum {
	AUL_APP_COM_R_OK = 0,
	AUL_APP_COM_R_ILLEGAL_ACCESS = -1,
} aul_app_com_result_e;

typedef struct _aul_app_com_permission_s aul_app_com_permission_s;
typedef aul_app_com_permission_s *aul_app_com_permission_h;
typedef struct _aul_app_com_connection_s aul_app_com_connection_s;
typedef aul_app_com_connection_s *aul_app_com_connection_h;

typedef int (*app_com_cb)(const char *endpoint, aul_app_com_result_e result, bundle *envelope, void *user_data);

/**
 * aul_app_com provides publish-subscribe style message for internal AUL use.
 * e.g) widget status propagation, sharing callee app status to caller app
 * @code

static int __handler(const char *endpoint, aul_app_com_result_e result, bundle *envelope, void *user_data)
{
	_D("endpoint: %s", endpoint);
	_D("result: %d", result);

	return 0;
}

// viewer-side
aul_app_com_permission_h permission = aul_app_com_permission_create();
aul_app_com_permission_set_propagation(permission, AUL_APP_COM_PRIVILEGED);
aul_app_com_permission_set_privilege(permission, "http://tizen.org/privilege/widget.viewer");
aul_app_com_connection_h connection = NULL;
aul_app_com_create("widget.status", permission, __handler, NULL, &connection);


// widget-side
bundle *b = bundle_create();
bundle_add_str(b, "WIDGET_ID", "org.example.widget");
bundle_add_str(b, "STATUS", "RUNNING");
aul_app_com_send("widget.status", b);
bundle_free(b);


// monitor-side
static int __handler(const char *endpoint, aul_app_com_result_e result, bundle *envelope, void *user_data)
{
	const char *widget_id = bundle_get_val(envelope, "WIDGET_ID");
	const char *status = bundle_get_val(envelope, "STATUS");

	_D("%s is %s", widget_id, status);

	return 0;
}

aul_app_com_connection_h connection = NULL;
aul_app_com_join("widget.status", NULL, __handler, NULL, &connection);

 */

aul_app_com_permission_h aul_app_com_permission_create();
void aul_app_com_permission_destroy(aul_app_com_permission_h permission);
int aul_app_com_permission_set_propagation(aul_app_com_permission_h permission, aul_app_com_propagate_option_e option);
int aul_app_com_permission_set_privilege(aul_app_com_permission_h permission, const char *privilege);


int aul_app_com_create(const char *endpoint, aul_app_com_permission_h permission, app_com_cb callback, void *user_data, aul_app_com_connection_h *connection);
int aul_app_com_join(const char *endpoint, const char *filter, app_com_cb callback, void *user_data, aul_app_com_connection_h *connection);
int aul_app_com_leave(aul_app_com_connection_h connection);
int aul_app_com_send(const char *endpoint, bundle *envelope);

#ifdef __cplusplus
}
#endif

#endif
