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

#include <amd_api_request.h>

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

enum amd_cynara_result {
	AMD_CYNARA_RET_ERROR = -2,
	AMD_CYNARA_RET_DENIED,
	AMD_CYNARA_RET_ALLOWED,
	AMD_CYNARA_RET_UNKNOWN,
	AMD_CYNARA_RET_CONTINUE,
};

typedef struct caller_info *amd_cynara_caller_info_h;

typedef int (*amd_cynara_checker_func)(amd_cynara_caller_info_h info, amd_request_h req,
		void *data);
typedef int (*amd_cynara_sub_checker_func)(amd_cynara_caller_info_h info, amd_request_h req);

typedef struct _amd_cynara_checker {
	int cmd;
	amd_cynara_checker_func checker;
	void *data;
	int priority;
} amd_cynara_checker;

typedef void (*amd_cynara_response_cb)(enum amd_cynara_result res, amd_request_h request);

typedef struct _amd_cynara_ops {
	int (*register_checkers)(const amd_cynara_checker *checkers, int cnt);
	int (*sub_checker_add)(const char *name, amd_cynara_sub_checker_func func);
	int (*sub_checker_check)(const char *name, amd_cynara_caller_info_h info, amd_request_h req);

	int (*check_async)(amd_request_h req, amd_cynara_response_cb callback);
	int (*check)(amd_cynara_caller_info_h info, amd_request_h req, void *data);
	int (*check_offline)(amd_request_h req, const char *appid, const char *privilege);
} amd_cynara_ops;

typedef struct _amd_cynara_caller_info_ops {
	const char *(*get_client)(amd_cynara_caller_info_h info);
} amd_cynara_caller_info_ops;

int amd_cynara_check_privilege(amd_request_h req, amd_cynara_response_cb callback);
int amd_cynara_check_privilege_offline(amd_request_h req, const char *appid, const char *privilege);
int amd_cynara_register_checkers(const amd_cynara_checker *checkers, int cnt);
int amd_cynara_simple_checker(amd_cynara_caller_info_h info, amd_request_h req, void *data);
const char *amd_cynara_caller_info_get_client(amd_cynara_caller_info_h info);
int amd_cynara_sub_checker_add(const char *name, amd_cynara_sub_checker_func func);
int amd_cynara_sub_checker_check(const char *name, amd_cynara_caller_info_h info, amd_request_h req);
int amd_cynara_register_ops(amd_cynara_ops ops, amd_cynara_caller_info_ops ci_ops);

