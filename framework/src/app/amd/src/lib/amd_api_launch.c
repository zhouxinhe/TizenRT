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
#include "amd_api_launch.h"
#include "amd_launch.h"

EXPORT_API int amd_launch_start_app(const char *appid, amd_request_h req, bool *pending,
		bool *bg_launch, bool new_instance)
{
	return _launch_start_app(appid, req, pending, bg_launch, new_instance);
}

EXPORT_API int amd_launch_term_sub_app(int pid, uid_t uid)
{
	return _term_sub_app(pid, uid);
}

EXPORT_API int amd_launch_start_onboot_apps(uid_t uid)
{
	return _launch_start_onboot_apps(uid);
}

EXPORT_API void amd_launch_set_mode(amd_launch_mode_e mode)
{
	_launch_set_mode(mode);
}
