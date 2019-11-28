/*
 * Copyright (c) 2014 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <string.h>
#include <aul.h>
#include <app/tizen_error.h>
#include <dlog.h>

#include "app_types.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "CAPI_APPFW_APPLICATION"

#define _STRDUP(s) ((s) ? strdup(s) : NULL)

char *app_get_data_path(void)
{
	const char *buf = aul_get_app_data_path();
	return _STRDUP(buf);
}

char *app_get_cache_path(void)
{
	const char *buf = aul_get_app_cache_path();
	return _STRDUP(buf);
}

char *app_get_resource_path(void)
{
	const char *buf = aul_get_app_resource_path();
	return _STRDUP(buf);
}

char *app_get_shared_data_path(void)
{
	int ret;
	char *path = NULL;

	ret = aul_get_app_shared_data_path(&path);
	if (ret == AUL_R_OK && path)
		set_last_result(APP_ERROR_NONE);
	else if (ret == AUL_R_EREJECTED)
		set_last_result(APP_ERROR_PERMISSION_DENIED);
	else
		set_last_result(APP_ERROR_OUT_OF_MEMORY);

	return path;
}

char *app_get_shared_resource_path(void)
{
	const char *buf = aul_get_app_shared_resource_path();
	return _STRDUP(buf);
}

char *app_get_shared_trusted_path(void)
{
	const char *buf = aul_get_app_shared_trusted_path();
	return _STRDUP(buf);
}

char *app_get_external_data_path(void)
{
	const char *buf = aul_get_app_external_data_path();
	return _STRDUP(buf);
}

char *app_get_external_cache_path(void)
{
	const char *buf = aul_get_app_external_cache_path();
	return _STRDUP(buf);
}

char *app_get_external_shared_data_path(void)
{
	dlog_print(DLOG_WARN, LOG_TAG, "DEPRECATION WARNING: app_get_external_shared_data_path() is deprecated and will be removed from next release.");
	const char *buf = aul_get_app_external_shared_data_path();
	return _STRDUP(buf);
}

char *app_get_tep_resource_path(void)
{
	const char *buf = aul_get_app_tep_resource_path();
	return _STRDUP(buf);
}

