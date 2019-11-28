/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include "amd_api.h"
#include "amd_api_app_property.h"
#include "amd_app_property.h"

EXPORT_API amd_app_property_h amd_app_property_find(uid_t uid)
{
	return _app_property_find(uid);
}

EXPORT_API int amd_app_property_metadata_add_filter(const char *key,
		const char *value)
{
	return _app_property_metadata_add_filter(key, value);
}

EXPORT_API int amd_app_property_metadata_remove_filter(const char *key,
		const char *value)
{
	return _app_property_metadata_remove_filter(key, value);
}

EXPORT_API int amd_app_property_metadata_foreach(
		amd_app_property_h app_property,
		const char *appid, const char *key,
		int (*callback)(const char *value, void *user_data),
		void *user_data)
{
	return _app_property_metadata_foreach(app_property, appid, key,
			callback, user_data);
}

EXPORT_API const char *amd_app_property_get_real_appid(
		amd_app_property_h app_property, const char *alias_appid)
{
	return _app_property_get_real_appid(app_property, alias_appid);
}
