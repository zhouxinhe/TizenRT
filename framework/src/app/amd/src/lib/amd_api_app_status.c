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
#include "amd_app_status.h"
#include "amd_api.h"
#include "amd_api_app_status.h"

EXPORT_API amd_app_status_h amd_app_status_find_by_effective_pid(int pid)
{
	return _app_status_find_v2(pid);
}

EXPORT_API amd_app_status_h amd_app_status_find_by_pid(int pid)
{
	return _app_status_find(pid);
}

EXPORT_API amd_app_status_h amd_app_status_find_by_appid(const char *appid,
		uid_t uid)
{
	return _app_status_find_by_appid(appid, uid);
}

EXPORT_API int amd_app_status_get_pid(amd_app_status_h h)
{
	return _app_status_get_pid(h);
}

EXPORT_API uid_t amd_app_status_get_uid(amd_app_status_h h)
{
	return _app_status_get_uid(h);
}

EXPORT_API int amd_app_status_get_status(amd_app_status_h h)
{
	return _app_status_get_status(h);
}

EXPORT_API bool amd_app_status_is_home_app(amd_app_status_h h)
{
	return _app_status_is_home_app(h);
}

EXPORT_API int amd_app_status_get_first_caller_pid(amd_app_status_h h)
{
	return _app_status_get_org_caller_pid(h);
}

EXPORT_API const char *amd_app_status_get_appid(amd_app_status_h h)
{
	return _app_status_get_appid(h);
}

EXPORT_API const char *amd_app_status_get_pkgid(amd_app_status_h h)
{
	return _app_status_get_pkgid(h);
}

EXPORT_API const char *amd_app_status_get_instance_id(amd_app_status_h h)
{
	return _app_status_get_instance_id(h);
}

EXPORT_API int amd_app_status_foreach_running_info(amd_app_status_cb callback,
		void *user_data)
{
	return _app_status_foreach_running_appinfo(callback, user_data);
}

EXPORT_API int amd_app_status_terminate_apps(const char *appid, uid_t uid)
{
	return _app_status_terminate_apps(appid, uid);
}

EXPORT_API bool amd_app_status_is_starting(amd_app_status_h h)
{
	return _app_status_is_starting(h);
}

EXPORT_API int amd_app_status_get_app_type(amd_app_status_h app_status)
{
	return _app_status_get_app_type(app_status);
}

EXPORT_API int amd_app_status_set_extra(amd_app_status_h app_status,
		const char *key, void *data)
{
	return _app_status_set_extra(app_status, key, data);
}

EXPORT_API int amd_app_status_remove_extra(amd_app_status_h app_status,
		const char *key)
{
	return _app_status_remove_extra(app_status, key);
}

EXPORT_API void *amd_app_status_get_extra(amd_app_status_h app_status,
		const char *key)
{
	return _app_status_get_extra(app_status, key);
}

EXPORT_API int amd_app_status_get_leader_pid(amd_app_status_h app_status)
{
	return _app_status_get_leader_pid(app_status);
}

EXPORT_API int amd_app_status_set_leader_pid(amd_app_status_h app_status, int pid)
{
	return _app_status_set_leader_pid(app_status, pid);
}

EXPORT_API int amd_app_status_get_fg_cnt(amd_app_status_h app_status)
{
	return _app_status_get_fg_cnt(app_status);
}

EXPORT_API int amd_app_status_get_timestamp(amd_app_status_h app_status)
{
	return _app_status_get_timestamp(app_status);
}

EXPORT_API int amd_app_status_term_bg_apps(GCompareFunc func)
{
	return _app_status_term_bg_apps(func);
}

EXPORT_API bool amd_app_status_get_bg_launch(amd_app_status_h app_status)
{
	return _app_status_get_bg_launch(app_status);
}

EXPORT_API amd_app_status_h amd_app_status_find_by_instance_id(const char *appid,
		const char *instance_id, uid_t uid)
{
	return _app_status_find_by_instance_id(appid, instance_id, uid);
}

EXPORT_API void amd_app_status_find_service_apps(amd_app_status_h app_status,
		int status, void (*send_event_to_svc_core)(int, uid_t),
		bool suspend)
{
	_app_status_find_service_apps(app_status, status,
			send_event_to_svc_core, suspend);
}

EXPORT_API int amd_app_status_get_process_cnt(const char *appid)
{
	return _app_status_get_process_cnt(appid);
}

EXPORT_API const char *amd_app_status_get_app_path(amd_app_status_h app_status)
{
	return _app_status_get_app_path(app_status);
}

EXPORT_API bool amd_app_status_is_exiting(amd_app_status_h app_status)
{
	return _app_status_is_exiting(app_status);
}

EXPORT_API int amd_app_status_register_pid(int pid, const char *appid,
		uid_t uid)
{
	return _app_status_register_pid(pid, appid, uid);
}
