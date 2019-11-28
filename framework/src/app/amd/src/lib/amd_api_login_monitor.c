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
#include "amd_api_login_monitor.h"
#include "amd_login_monitor.h"

EXPORT_API int amd_login_monitor_get_uids(uid_t **uids)
{
	return _login_monitor_get_uids(uids);
}

EXPORT_API amd_uid_state amd_login_monitor_get_uid_state(uid_t uid)
{
	return _login_monitor_get_uid_state(uid);
}
