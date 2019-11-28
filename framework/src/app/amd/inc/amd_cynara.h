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

#include "amd_request.h"

#define SYSPOPUP_NAME "_INTERNAL_SYSPOPUP_NAME_"
#define PRIVILEGE_WIDGET_VIEWER \
	"http://tizen.org/privilege/widget.viewer"
#define PRIVILEGE_APPMANAGER_LAUNCH \
	"http://tizen.org/privilege/appmanager.launch"
#define PRIVILEGE_APPMANAGER_KILL \
	"http://tizen.org/privilege/appmanager.kill"
#define PRIVILEGE_APPMANAGER_KILL_BGAPP \
	"http://tizen.org/privilege/appmanager.kill.bgapp"
#define PRIVILEGE_DOWNLOAD \
	"http://tizen.org/privilege/download"
#define PRIVILEGE_CALL \
	"http://tizen.org/privilege/call"
#define PRIVILEGE_SYSTEM_SETTING \
	"http://tizen.org/privilege/systemsettings.admin"
#define PRIVILEGE_PLATFORM \
	"http://tizen.org/privilege/internal/default/platform"

enum amd_cynara_res {
	AMD_CYNARA_ERROR = -2,
	AMD_CYNARA_DENIED,
	AMD_CYNARA_ALLOWED,
	AMD_CYNARA_UNKNOWN,
	AMD_CYNARA_CONTINUE,
};

typedef struct caller_info *caller_info_h;

typedef int (*checker_func)(caller_info_h info, request_h req,
		void *data);
typedef int (*sub_checker_func)(caller_info_h info, request_h req);

typedef struct _cynara_checker {
	int cmd;
	checker_func checker;
	void *data;
	int priority;
} cynara_checker;

typedef void (*cynara_response_cb)(enum amd_cynara_res res, request_h request);

typedef struct _cynara_ops {
	int (*register_checkers)(const cynara_checker *checkers, int cnt);
	int (*sub_checker_add)(const char *name, sub_checker_func func);
	int (*sub_checker_check)(const char *name, caller_info_h info, request_h req);

	int (*check_async)(request_h req, cynara_response_cb callback);
	int (*check)(caller_info_h info, request_h req, void *data);
	int (*check_offline)(request_h req, const char *appid, const char *privilege);
} cynara_ops;

typedef struct _cynara_caller_info_ops {
	const char *(*get_client)(caller_info_h info);
} cynara_caller_info_ops;

int _cynara_init(void);
void _cynara_finish(void);
int _cynara_check_privilege(request_h req, cynara_response_cb callback);
int _cynara_check_privilege_offline(request_h req, const char *appid, const char *privilege);
int _cynara_register_checkers(const cynara_checker *checkers, int cnt);
int _cynara_simple_checker(caller_info_h info, request_h req, void *data);
const char *_cynara_caller_info_get_client(caller_info_h info);
int _cynara_sub_checker_add(const char *name, sub_checker_func func);
int _cynara_sub_checker_check(const char *name, caller_info_h info, request_h req);
int _cynara_register_ops(cynara_ops ops, cynara_caller_info_ops ci_ops);

