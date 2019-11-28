/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <stdio.h>
#include <stdlib.h>
#include <aul.h>
#include <aul_cmd.h>
#include <aul_sock.h>
#include <bundle_internal.h>
#include <amd.h>

#include "amd_complication_private.h"

#define ARRAY_SIZE(x) ((sizeof(x)) / sizeof(x[0]))
#define MAX_NR_OF_DESCRIPTORS 2
#define PRIVILEGE_DATASHARING "http://tizen.org/privilege/datasharing"

static int __dispatch_complication_start(amd_request_h req)
{
	bundle *b = amd_request_get_bundle(req);
	pid_t caller_pid = amd_request_get_pid(req);
	uid_t target_uid = amd_request_get_target_uid(req);
	amd_appinfo_h ai;
	const char *appid;
	const char *comp_type;
	int pid;
	bool dummy_pending = false;
	bool dummy_bg_launch = false;

	if (!b) {
		_E("Invalid parameter");
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	appid = bundle_get_val(b, AUL_K_APPID);
	if (!appid) {
		_E("Failed to get appid");
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	ai = amd_appinfo_find(target_uid, appid);
	if (!ai) {
		_E("Failed to find %s:%u", appid, target_uid);
		amd_request_send_result(req, -ENOENT);
		return -1;
	}

	comp_type = amd_appinfo_get_value(ai, AMD_AIT_COMPTYPE);
	if (!comp_type) {
		amd_request_send_result(req, -1);
		return -1;
	}

	if (strcmp(comp_type, APP_TYPE_SERVICE) != 0) {
		_E("Target(%s) is not a service-app", appid);
		amd_request_send_result(req, -EREJECTED);
		return -1;
	}

	amd_request_set_request_type(req, "complication");
	amd_request_set_cmd(req, APP_START_ASYNC);
	pid = amd_launch_start_app(appid, req,
			&dummy_pending, &dummy_bg_launch,
			false);
	if (pid < 0) {
		_E("Failed to send launch request(%s)",
				appid);
		return -1;
	}

	_I("[__COMPLICATION__] appid(%s), pid(%d), caller_pid(%d)",
			appid, pid, caller_pid);

	return 0;
}

static int __complication_cynara_checker(amd_cynara_caller_info_h info,
		amd_request_h req, void *data)
{
	int r;

	r =  amd_cynara_simple_checker(info, req, PRIVILEGE_APPMANAGER_LAUNCH);
	if (r <= AMD_CYNARA_RET_DENIED)
		return r;

	return amd_cynara_simple_checker(info, req, PRIVILEGE_DATASHARING);
}


static amd_request_cmd_dispatch __dispatch_table[] = {
	{
		.cmd = COMPLICATION_UPDATE_REQUEST,
		.callback = __dispatch_complication_start
	},
};

static amd_cynara_checker __cynara_checkers[] = {
	{
		.cmd = COMPLICATION_UPDATE_REQUEST,
		.checker = __complication_cynara_checker,
		.data = NULL,
		.priority = 10
	},
};

EXPORT int AMD_MOD_INIT(void)
{
	int r;

	_D("complication init");

	r = amd_request_register_cmds(__dispatch_table,
			ARRAY_SIZE(__dispatch_table));
	if (r < 0) {
		_E("Failed to register cmds");
		return -1;
	}

	r = amd_cynara_register_checkers(__cynara_checkers,
			ARRAY_SIZE(__cynara_checkers));
	if (r < 0) {
		_E("Failed to register cynara checkers");
		return -1;
	}

	return 0;
}

EXPORT void AMD_MOD_FINI(void)
{
	_D("complication finish");
}
