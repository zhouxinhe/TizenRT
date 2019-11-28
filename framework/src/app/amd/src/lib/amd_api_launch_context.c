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
#include "amd_launch.h"
#include "amd_api.h"
#include "amd_api_launch_context.h"

EXPORT_API amd_appinfo_h amd_launch_context_get_appinfo(
		amd_launch_context_h h)
{
	return (amd_appinfo_h)_launch_context_get_appinfo(h);
}

EXPORT_API const char *amd_launch_context_get_appid(amd_launch_context_h h)
{
	return _launch_context_get_appid(h);
}

EXPORT_API const char *amd_launch_context_get_instance_id(
		amd_launch_context_h h)
{
	return _launch_context_get_instance_id(h);
}

EXPORT_API int amd_launch_context_get_pid(amd_launch_context_h h)
{
	return _launch_context_get_pid(h);
}

EXPORT_API bool amd_launch_context_is_subapp(amd_launch_context_h h)
{
	return _launch_context_is_subapp(h);
}

EXPORT_API bool amd_launch_context_is_bg_launch(amd_launch_context_h h)
{
	return _launch_context_is_bg_launch(h);
}

EXPORT_API int amd_launch_context_set_pid(amd_launch_context_h h,
		int pid)
{
	return _launch_context_set_pid(h, pid);
}

EXPORT_API bool amd_launch_context_is_new_instance(amd_launch_context_h h)
{
	return _launch_context_is_new_instance(h);
}

EXPORT_API int amd_launch_context_set_subapp(amd_launch_context_h h,
		bool is_subapp)
{
	return _launch_context_set_subapp(h, is_subapp);
}

EXPORT_API int amd_launch_context_set_app_status(amd_launch_context_h h,
		amd_app_status_h status)
{
	return _launch_context_set_app_status(h, status);
}

