/*
 * Copyright (c) 2015 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <unistd.h>
#include <sys/types.h>
#include <glib.h>
#include <stdbool.h>

#include "amd_appinfo.h"

typedef enum {
	AT_SERVICE_APP,
	AT_UI_APP,
	AT_WIDGET_APP,
	AT_WATCH_APP,
} app_type_e;

typedef struct app_status_s *app_status_h;

int _app_status_register_pid(int pid, const char *appid, uid_t uid);
int _app_status_set_extra(app_status_h app_status, const char *key, void *data);
int _app_status_remove_extra(app_status_h app_status, const char *key);
void *_app_status_get_extra(app_status_h app_status, const char *key);
int _app_status_add_app_info(const struct appinfo *ai, int pid,
		bool is_subapp, uid_t uid, int caller_pid,
		bool bg_launch, const char *instance_id,
		bool debug_mode);
int _app_status_remove_all_app_info_with_uid(uid_t uid);
int _app_status_remove(app_status_h app_status);
int _app_status_update_status(app_status_h app_status, int status, bool force,
		bool update_group_info);
int _app_status_update_last_caller_pid(app_status_h app_status, int caller_pid);
int _app_status_update_bg_launch(app_status_h app_status, bool bg_launch);
int _app_status_get_process_cnt(const char *appid);
bool _app_status_is_home_app(app_status_h app_status);
int _app_status_get_pid(app_status_h app_status);
int _app_status_get_last_caller_pid(app_status_h app_status);
int _app_status_is_running(app_status_h app_status);
int _app_status_get_status(app_status_h app_status);
uid_t _app_status_get_uid(app_status_h app_status);
const char *_app_status_get_appid(app_status_h app_status);
const char *_app_status_get_pkgid(app_status_h app_status);
int _app_status_get_leader_pid(app_status_h app_status);
int _app_status_set_leader_pid(app_status_h app_status, int pid);
int _app_status_get_fg_cnt(app_status_h app_status);
int _app_status_get_timestamp(app_status_h app_status);
int _app_status_term_bg_apps(GCompareFunc func);
bool _app_status_get_bg_launch(app_status_h app_status);
const char *_app_status_get_instance_id(app_status_h app_stauts);
int _app_status_get_app_type(app_status_h app_status);
bool _app_status_socket_exists(app_status_h app_status);
bool _app_status_is_starting(app_status_h app_status);
int _app_status_update_is_starting(app_status_h app_status, bool is_starting);
bool _app_status_is_exiting(app_status_h app_status);
int _app_status_update_is_exiting(app_status_h app_status, bool is_exiting);
const char *_app_status_get_app_path(app_status_h app_status);
app_status_h _app_status_find(int pid);
app_status_h _app_status_find_v2(int pid);
app_status_h _app_status_find_by_appid(const char *appid, uid_t uid);
app_status_h _app_status_find_by_appid_v2(const char *appid, uid_t uid);
app_status_h _app_status_find_with_org_caller(const char *appid, uid_t uid,
		int caller_pid);
app_status_h _app_status_find_by_instance_id(const char *appid,
		const char *instance_id, uid_t uid);
void _app_status_find_service_apps(app_status_h app_status, int status,
		void (*send_event_to_svc_core)(int, uid_t), bool suspend);
void _app_status_check_service_only(app_status_h app_status,
		void (*send_event_to_svc_core)(int, uid_t));
int _app_status_send_running_appinfo(int fd, int cmd, uid_t uid);
int _app_status_foreach_running_appinfo(void (*callback)(app_status_h, void *),
		void *data);
int _app_status_terminate_apps(const char *appid, uid_t uid);
int _app_status_terminate_apps_by_pkgid(const char *pkgid, uid_t uid);
int _app_status_get_appid_bypid(int fd, int pid);
int _app_status_get_pkgid_bypid(int fd, int pid);
int _app_status_get_instance_id_bypid(int fd, int pid);
int _app_status_get_org_caller_pid(app_status_h app_status);
int _app_status_publish_status(int pid, int context_status);
void _app_status_cleanup(app_status_h app_status);
int _app_status_usr_init(uid_t uid);
void _app_status_usr_fini(uid_t uid);
int _app_status_init(void);
int _app_status_finish(void);
