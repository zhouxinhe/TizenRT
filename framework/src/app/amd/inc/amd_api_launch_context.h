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

#include <amd_api_appinfo.h>
#include <amd_api_app_status.h>

typedef struct launch_s *amd_launch_context_h;

amd_appinfo_h amd_launch_context_get_appinfo(amd_launch_context_h h);
const char *amd_launch_context_get_appid(amd_launch_context_h h);
const char *amd_launch_context_get_instance_id(amd_launch_context_h h);
int amd_launch_context_get_pid(amd_launch_context_h h);
bool amd_launch_context_is_subapp(amd_launch_context_h h);
bool amd_launch_context_is_bg_launch(amd_launch_context_h h);
int amd_launch_context_set_pid(amd_launch_context_h h, int pid);
bool amd_launch_context_is_new_instance(amd_launch_context_h h);
int amd_launch_context_set_subapp(amd_launch_context_h h, bool is_subapp);
int amd_launch_context_set_app_status(amd_launch_context_h h, amd_app_status_h status);

