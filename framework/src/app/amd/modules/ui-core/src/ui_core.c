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

#include <dlog.h>

#include "amd.h"
#include "amd_screen_connector.h"
#include "amd_app_group.h"

#undef LOG_TAG
#define LOG_TAG "AMD_UI_CORE"

#undef EXPORT
#define EXPORT __attribute__ ((visibility("default")))

EXPORT int AMD_MOD_INIT(void)
{
	LOGD("ui-core init");
	if (_app_group_init() < 0)
		return -1;

	if (_screen_connector_init() < 0)
		return -1;

	return 0;
}

EXPORT void AMD_MOD_FINI(void)
{
	LOGD("ui-core fini");
	_screen_connector_fini();
	_app_group_fini();
}

