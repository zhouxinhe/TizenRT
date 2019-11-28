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

#ifndef __AMD_LOGIN_MONITOR_H__
#define __AMD_LOGIN_MOINTOR_H__

#include <unistd.h>
#include <sys/types.h>

typedef enum uid_state_e {
	UID_STATE_UNKNOWN = 0x00,
	UID_STATE_OPENING = 0x01,
	UID_STATE_LINGERING = 0x02,
	UID_STATE_ONLINE = 0x04,
	UID_STATE_ACTIVE = 0x08,
	UID_STATE_CLOSING = 0x10,
	UID_STATE_OFFLINE = 0x20,
} uid_state;

pid_t _login_monitor_get_launchpad_pid(uid_t uid);
void _login_monitor_set_uid_state(uid_t uid, uid_state state);
uid_state _login_monitor_get_uid_state(uid_t uid);
int _login_monitor_get_uids(uid_t **uids);
int _login_monitor_init(void);
void _login_monitor_fini(void);

#endif /* __AMD_LOGIN_MONITOR_H__ */
