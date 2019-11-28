/*
 * Copyright (c) 2017 Samsung Electronics Co., Ltd All Rights Reserved
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
#include "amd_appinfo.h"
#include "amd_api_appinfo.h"

EXPORT_API int amd_appinfo_insert(uid_t uid, const char *pkgid)
{
	return _appinfo_insert(uid, pkgid);
}

EXPORT_API amd_appinfo_h amd_appinfo_find(uid_t caller_uid, const char *appid)
{
	return _appinfo_find(caller_uid, appid);
}

EXPORT_API const char *amd_appinfo_get_value(amd_appinfo_h h,
		amd_appinfo_type type)
{
	return _appinfo_get_value(h, (enum appinfo_type)type);
}

EXPORT_API const void *amd_appinfo_get_ptr_value(amd_appinfo_h h,
		amd_appinfo_type type)
{
	return _appinfo_get_ptr_value(h, (enum appinfo_type)type);
}

EXPORT_API int amd_appinfo_get_int_value(amd_appinfo_h h, amd_appinfo_type type,
		int *val)
{
	return _appinfo_get_int_value(h, (enum appinfo_type)type, val);
}

EXPORT_API int amd_appinfo_get_boolean(amd_appinfo_h h, amd_appinfo_type type,
		bool *val)
{
	return _appinfo_get_boolean(h, (enum appinfo_type)type, val);
}

EXPORT_API int amd_appinfo_set_value(amd_appinfo_h h, amd_appinfo_type type,
		const char *val)
{
	return _appinfo_set_value(h, (enum appinfo_type)type, val);
}

EXPORT_API int amd_appinfo_set_ptr_value(amd_appinfo_h h, amd_appinfo_type type,
		void *val)
{
	return _appinfo_set_ptr_value(h, (enum appinfo_type)type, val);
}

EXPORT_API int amd_appinfo_set_int_value(amd_appinfo_h h, amd_appinfo_type type,
		int val)
{
	return _appinfo_set_int_value(h, (enum appinfo_type)type, val);
}

EXPORT_API void amd_appinfo_foreach(uid_t uid, amd_appinfo_iter_callback cb,
		void *user_data)
{
	return _appinfo_foreach(uid, cb, user_data);
}

EXPORT_API int amd_appinfo_load(uid_t uid)
{
	return _appinfo_load(uid);
}

EXPORT_API void amd_appinfo_unload(uid_t uid)
{
	return _appinfo_unload(uid);
}

EXPORT_API amd_appinfo_splash_image_h amd_appinfo_find_splash_image(
		amd_appinfo_h h, const char *name, bool landscape)
{
	return _appinfo_find_splash_image(h, name, landscape);
}

EXPORT_API const char *amd_appinfo_splash_image_get_source(
		amd_appinfo_splash_image_h h)
{
	return _appinfo_splash_image_get_source(h);
}

EXPORT_API const char *amd_appinfo_splash_image_get_type(
		amd_appinfo_splash_image_h h)
{
	return _appinfo_splash_image_get_type(h);
}

EXPORT_API int amd_appinfo_splash_image_get_indicator_display(
		amd_appinfo_splash_image_h h)
{
	return _appinfo_splash_image_get_indicator_display(h);
}

EXPORT_API int amd_appinfo_splash_image_get_color_depth(
		amd_appinfo_splash_image_h h)
{
	return _appinfo_splash_image_get_color_depth(h);
}

EXPORT_API bool amd_appinfo_is_pkg_updating(const char *pkgid)
{
	return _appinfo_is_pkg_updating(pkgid);
}

EXPORT_API int amd_appinfo_get_cert_visibility(const char *pkgid, uid_t uid)
{
	return _appinfo_get_cert_visibility(pkgid, uid);
}
