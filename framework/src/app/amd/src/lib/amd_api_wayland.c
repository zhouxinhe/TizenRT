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
#include "amd_api.h"
#include "amd_api_wayland.h"

static void *__display;
static void *__tizen_policy;

EXPORT_API void *amd_wayland_get_display(void)
{
	return __display;
}

EXPORT_API void amd_wayland_set_display(void *display)
{
	__display = display;
}

EXPORT_API void *amd_wayland_get_tizen_policy(void)
{
	return __tizen_policy;
}

EXPORT_API void amd_wayland_set_tizen_policy(void *tizen_policy)
{
	__tizen_policy = tizen_policy;
}
