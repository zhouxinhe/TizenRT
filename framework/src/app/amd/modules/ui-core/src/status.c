/*
 * Copyright (c) 2019 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <sys/types.h>
#include <unistd.h>
#include <dlog.h>
#include <amd.h>

#include "status.h"

#undef LOG_TAG
#define LOG_TAG "AMD_UI_CORE"

pid_t _status_get_effective_pid(pid_t pid)
{
	amd_app_status_h app_status;

	app_status = amd_app_status_find_by_effective_pid(pid);
	if (!app_status) {
		LOGW("Failed to find app status info. pid(%d)", pid);
		return -1;
	}

	return amd_app_status_get_pid(app_status);
}
