/*
 * Copyright (c) 2016 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
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

#include "amd_appinfo.h"

#define SUSPEND_TYPE_EXCLUDE "exclude"
#define SUSPEND_TYPE_INCLUDE "include"

enum suspend_status_e {
	SUSPEND_STATUS_EXCLUDE,
	SUSPEND_STATUS_INCLUDE,
};

enum background_category_e {
	BACKGROUND_CATEGORY_MEDIA = 0x01,
	BACKGROUND_CATEGORY_DOWNLOAD = 0x02,
	BACKGROUND_CATEGORY_BACKGROUND_NETWORK = 0x04,
	BACKGROUND_CATEGORY_LOCATION = 0x08,
	BACKGROUND_CATEGORY_SENSOR = 0x10,
	BACKGROUND_CATEGORY_IOT_COMMUNICATION = 0x20,
	BACKGROUND_CATEGORY_SYSTEM = 0x40
};

bool _suspend_is_allowed_background(const struct appinfo *ai);
void _suspend_add_timer(int pid);
void _suspend_remove_timer(int pid);
int _suspend_add_proc(int pid);
int _suspend_remove_proc(int pid);
int _suspend_update_status(int pid, int status);
void _suspend_init(void);
void _suspend_fini(void);
