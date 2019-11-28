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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <glib.h>
#include <aul.h>
#include <amd.h>

#include "amd_cooldown.h"

#define APP_SUPPORT_MODE_VIP_APPLICATION 0x00000010
#define COOLDOWN_STATUS_RELEASEACTION "ReleaseAction"
#define COOLDOWN_STATUS_LIMITACTION "LimitAction"

enum cooldown_status_val {
	COOLDOWN_RELEASE,
	COOLDOWN_WARNING,
	COOLDOWN_LIMIT,
};

static int cooldown_status;

static void __cooldown_limitaction(amd_app_status_h app_status, void *data)
{
	amd_appinfo_h ai;
	const char *taskmanage;
	const char *cooldown;
	const char *appid;
	int app_type;
	uid_t uid;

	if (app_status == NULL)
		return;

	app_type = amd_app_status_get_app_type(app_status);
	if (app_type == AMD_AT_WIDGET_APP || app_type == AMD_AT_WATCH_APP)
		return;

	uid = amd_app_status_get_uid(app_status);
	appid = amd_app_status_get_appid(app_status);
	ai = amd_appinfo_find(uid, appid);
	if (ai == NULL)
		return;

	cooldown = amd_appinfo_get_value(ai, AMD_AIT_COOLDOWN);
	if (cooldown && strcmp(cooldown, "true") != 0) {
		if (app_type == AMD_AT_UI_APP) {
			taskmanage = amd_appinfo_get_value(ai,
					AMD_AIT_TASKMANAGE);
			if (taskmanage && strcmp(taskmanage, "true") != 0)
				return;
		}

		amd_app_status_terminate_apps(appid, uid);
	}
}

static void __cooldown_release(void)
{
	amd_uid_state state;
	uid_t *uids;
	int r;
	int i;

	r = amd_login_monitor_get_uids(&uids);
	if (r <= 0)
		return;

	for (i = 0; i < r; ++i) {
		state = amd_login_monitor_get_uid_state(uids[i]);
		if (state == AMD_UID_STATE_ACTIVE)
			amd_launch_start_onboot_apps(uids[i]);
	}
	free(uids);
}

static int __cooldown_signal_cb(const char *status, void *data)
{
	_W("[__COOLDOWN__] status %s", status);
	if (strcmp(status, COOLDOWN_STATUS_LIMITACTION) == 0) {
		cooldown_status = COOLDOWN_LIMIT;
		amd_app_status_foreach_running_info(__cooldown_limitaction,
				NULL);
	} else if (strcmp(status, COOLDOWN_STATUS_RELEASEACTION) == 0 &&
			cooldown_status != COOLDOWN_RELEASE) {
		cooldown_status = COOLDOWN_RELEASE;
		__cooldown_release();
	}

	return 0;
}

static int __check_cooldown_mode(amd_appinfo_h ai)
{
	const char *taskmanage;
	const char *cooldown;
	const char *comptype;

	if (cooldown_status != COOLDOWN_LIMIT)
		return 0;

	cooldown = amd_appinfo_get_value(ai, AMD_AIT_COOLDOWN);
	if (cooldown && strcmp(cooldown, "true") == 0)
		return 0;

	comptype = amd_appinfo_get_value(ai, AMD_AIT_COMPTYPE);
	if (comptype == NULL) {
		_E("Failed to get comptype");
		return -1;
	}

	if (strcmp(comptype, APP_TYPE_WIDGET) == 0 ||
			strcmp(comptype, APP_TYPE_WATCH) == 0)
		return 0;

	if (strcmp(comptype, APP_TYPE_UI) == 0) {
		taskmanage = amd_appinfo_get_value(ai, AMD_AIT_TASKMANAGE);
		if (taskmanage && strcmp(taskmanage, "false") == 0)
			return 0;
	}

	_W("Cannot launch this application in COOLDOWN mode");
	return -1;
}

static int __on_check_mode(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	amd_appinfo_h info = arg3;

	return __check_cooldown_mode(info);
}

static int __on_check_status(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	if (cooldown_status == COOLDOWN_LIMIT)
		return -1;

	return 0;
}

EXPORT int AMD_MOD_INIT(void)
{
	int r;

	_D("cooldown init");
	r = aul_listen_cooldown_signal(__cooldown_signal_cb, NULL);
	if (r < 0)
		return -1;

	amd_noti_listen("launch.prepare.start", __on_check_mode);
	amd_noti_listen("signal.send_watchdog.start", __on_check_status);

	return 0;
}

EXPORT void AMD_MOD_FINI(void)
{
	_D("cooldown fini");
	aul_listen_cooldown_signal(NULL, NULL);
}
