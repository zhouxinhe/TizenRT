/*
 * Copyright (c) 2016 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
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
#include "amd_suspend.h"
#include "amd_api_suspend.h"

EXPORT_API int amd_suspend_add_proc(int pid)
{
	return _suspend_add_proc(pid);
}

EXPORT_API int amd_suspend_remove_proc(int pid)
{
	return _suspend_remove_proc(pid);
}

EXPORT_API bool amd_suspend_is_allowed_background(amd_appinfo_h ai)
{
	return _suspend_is_allowed_background(ai);
}

EXPORT_API void amd_suspend_add_timer(int pid)
{
	 _suspend_add_timer(pid);
}

EXPORT_API void amd_suspend_remove_timer(int pid)
{
	_suspend_remove_timer(pid);
}

EXPORT_API int amd_suspend_update_status(int pid, int status)
{
	return _suspend_update_status(pid, status);
}

