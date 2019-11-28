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

#pragma once

#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

typedef enum {
	AMD_AT_SERVICE_APP,
	AMD_AT_UI_APP,
	AMD_AT_WIDGET_APP,
	AMD_AT_WATCH_APP,
} amd_app_type_e;

typedef struct app_status_s *amd_app_status_h;
typedef void (*amd_app_status_cb)(amd_app_status_h h, void *user_data);

amd_app_status_h amd_app_status_find_by_effective_pid(int pid);
amd_app_status_h amd_app_status_find_by_pid(int pid);
amd_app_status_h amd_app_status_find_by_appid(const char *appid, uid_t uid);
int amd_app_status_get_pid(amd_app_status_h h);
uid_t amd_app_status_get_uid(amd_app_status_h h);
int amd_app_status_get_status(amd_app_status_h h);
bool amd_app_status_is_home_app(amd_app_status_h h);
int amd_app_status_get_first_caller_pid(amd_app_status_h h);
const char *amd_app_status_get_appid(amd_app_status_h h);
const char *amd_app_status_get_pkgid(amd_app_status_h h);
const char *amd_app_status_get_instance_id(amd_app_status_h h);
int amd_app_status_foreach_running_info(amd_app_status_cb callback,
		void *user_data);
int amd_app_status_terminate_apps(const char *appid, uid_t uid);
bool amd_app_status_is_starting(amd_app_status_h h);
int amd_app_status_get_app_type(amd_app_status_h app_status);
int amd_app_status_set_extra(amd_app_status_h app_status, const char *key, void *data);
int amd_app_status_remove_extra(amd_app_status_h app_status, const char *key);
void *amd_app_status_get_extra(amd_app_status_h app_status, const char *key);

int amd_app_status_get_leader_pid(amd_app_status_h app_status);
int amd_app_status_set_leader_pid(amd_app_status_h app_status, int pid);
int amd_app_status_get_fg_cnt(amd_app_status_h app_status);
int amd_app_status_get_timestamp(amd_app_status_h app_status);
int amd_app_status_term_bg_apps(GCompareFunc func);
bool amd_app_status_get_bg_launch(amd_app_status_h app_status);
amd_app_status_h amd_app_status_find_by_instance_id(const char *appid,
		const char *instance_id, uid_t uid);
void amd_app_status_find_service_apps(amd_app_status_h app_status, int status,
		void (*send_event_to_svc_core)(int, uid_t), bool suspend);
int amd_app_status_get_process_cnt(const char *appid);
const char *amd_app_status_get_app_path(amd_app_status_h app_status);
bool amd_app_status_is_exiting(amd_app_status_h app_status);
int amd_app_status_register_pid(int pid, const char *appid, uid_t uid);
