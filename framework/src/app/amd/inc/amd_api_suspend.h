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
#include <amd_api_appinfo.h>

#define AMD_SUSPEND_TYPE_EXCLUDE "exclude"
#define AMD_SUSPEND_TYPE_INCLUDE "include"

enum amd_suspend_status_e {
	AMD_SUSPEND_STATUS_EXCLUDE,
	AMD_SUSPEND_STATUS_INCLUDE,
};

enum amd_background_category_e {
	AMD_BACKGROUND_CATEGORY_MEDIA = 0x01,
	AMD_BACKGROUND_CATEGORY_DOWNLOAD = 0x02,
	AMD_BACKGROUND_CATEGORY_BACKGROUND_NETWORK = 0x04,
	AMD_BACKGROUND_CATEGORY_LOCATION = 0x08,
	AMD_BACKGROUND_CATEGORY_SENSOR = 0x10,
	AMD_BACKGROUND_CATEGORY_IOT_COMMUNICATION = 0x20,
	AMD_BACKGROUND_CATEGORY_SYSTEM = 0x40
};

bool amd_suspend_is_allowed_background(amd_appinfo_h ai);
void amd_suspend_add_timer(int pid);
void amd_suspend_remove_timer(int pid);
int amd_suspend_add_proc(int pid);
int amd_suspend_remove_proc(int pid);
int amd_suspend_update_status(int pid, int status);
