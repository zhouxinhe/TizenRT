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

#define RESOURCED_ATTRIBUTE_LARGEMEMORY		0x01
#define RESOURCED_ATTRIBUTE_OOMTERMINATION	0X02
#define RESOURCED_ATTRIBUTE_WEB_APP		0x04
#define RESOURCED_ATTRIBUTE_DOWNLOAD_APP	0x08
#define RESOURCED_ATTRIBUTE_SERVICE_APP		0x10
#define RESOURCED_ATTRIBUTE_VIP_APP		0x20

typedef enum {
	POWEROFF_NONE = 0,
	POWEROFF_POPUP,
	POWEROFF_DIRECT,
	POWEROFF_RESTART,
} poweroff_e;

int _signal_init(void);
int _signal_send_watchdog(int pid, int signal_num);
int _signal_send_proc_prelaunch(const char *appid, const char *pkgid,
		int attribute, int category);
int _signal_send_proc_suspend(int pid);
int _signal_send_tep_mount(char *mnt_path[], const char *pkgid);
int _signal_send_tep_unmount(const char *mnt_path);
int _signal_get_proc_status(const int pid, int *status, int *focused);
int _signal_subscribe_startup_finished(int (*callback)(uid_t uid, void *data),
		void *user_data);
int _signal_unsubscribe_startup_finished(void);
int _signal_send_display_lock_state(const char *state, const char *flag,
		unsigned int timeout);
int _signal_send_system_service(int pid);
int _signal_send_display_unlock_state(const char *state, const char *flag);
int _signal_add_initializer(int (*callback)(void *data), void *user_data);
int _signal_subscribe_poweroff_state(void (*callback)(int state, void *data),
		void *user_data);
