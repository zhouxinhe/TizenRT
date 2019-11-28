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

#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <bundle.h>

#include "amd_request.h"
#include "amd_util.h"
#include "amd_appinfo.h"
#include "amd_app_status.h"

#define PROC_STATUS_LAUNCH 0
#define PROC_STATUS_FG 3
#define PROC_STATUS_BG 4
#define PROC_STATUS_FOCUS 5
#define PROC_STATUS_HIDE 7

typedef struct launch_s *launch_h;

typedef enum {
	LAUNCH_MODE_NORMAL,
	LAUNCH_MODE_BLOCK,
} launch_mode_e;

int _resume_app(int pid, request_h req);
int _pause_app(int pid, request_h req);
int _term_app(int pid, request_h req);
int _term_req_app(int pid, request_h req);
int _term_bgapp(int pid, request_h req);
int _term_sub_app(int pid, uid_t uid);
int _launch_start_app(const char *appid, request_h req, bool *pending,
		bool *bg_launch, bool new_instance);
int _launch_start_app_local(uid_t uid, const char *appid);
int _launch_start_app_local_with_bundle(uid_t uid, const char *appid,
		bundle *kb);
int _launch_start_onboot_app_local(uid_t uid, const char *appid,
		struct appinfo *ai);
int _launch_init(void);
void _launch_set_focused_pid(int pid);
int _launch_get_focused_pid(void);
int _term_app_v2(int pid, request_h req, bool *pend);
int _launch_start_onboot_apps(uid_t uid);
int _terminate_app_local(uid_t uid, int pid);
int _launch_context_get_pid(launch_h h);
int _launch_context_set_pid(launch_h h, int pid);
const char *_launch_context_get_appid(launch_h h);
bool _launch_context_is_new_instance(launch_h h);
int _launch_context_set_subapp(launch_h h, bool is_subapp);
int _launch_context_set_app_status(launch_h h, app_status_h status);
const char *_launch_context_get_instance_id(launch_h h);
bool _launch_context_is_subapp(launch_h h);
bool _launch_context_is_bg_launch(launch_h h);
const struct appinfo *_launch_context_get_appinfo(launch_h h);
void _launch_set_mode(launch_mode_e mode);

