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

#include <unistd.h>
#include <sys/types.h>

typedef enum amd_uid_state_e {
	AMD_UID_STATE_UNKNOWN = 0x00,
	AMD_UID_STATE_OPENING = 0x01,
	AMD_UID_STATE_LINGERING = 0x02,
	AMD_UID_STATE_ONLINE = 0x04,
	AMD_UID_STATE_ACTIVE = 0x08,
	AMD_UID_STATE_CLOSING = 0x10,
	AMD_UID_STATE_OFFLINE = 0x20,
} amd_uid_state;

int amd_login_monitor_get_uids(uid_t **uids);
amd_uid_state amd_login_monitor_get_uid_state(uid_t uid);
