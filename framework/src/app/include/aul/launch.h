/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <glib.h>

int aul_initialize();
int aul_is_initialized();
int aul_app_register_pid(const char *appid, int pid);

int app_send_cmd(int pid, int cmd, bundle *kb);
int app_send_cmd_for_uid(int pid, uid_t uid, int cmd, bundle *kb);
int app_send_cmd_with_noreply(int pid, int cmd, bundle *kb);
int app_send_cmd_to_launchpad(const char *pad_type, uid_t uid, int cmd, bundle *kb);
int app_request_to_launchpad(int cmd, const char *pkgname, bundle *kb);
int app_request_to_launchpad_for_uid(int cmd, const char *pkgname, bundle *kb, uid_t uid);

int app_result(int cmd, bundle *kb, int launched_pid);
int aul_send_result(bundle *kb, int is_cancel);
int aul_launch_app_with_result(const char *pkgname, bundle *kb,
			       void (*cbfunc) (bundle *, int, void *),
			       void *data);
int aul_launch_app_with_result_for_uid(const char *pkgname, bundle *kb,
			       void (*cbfunc) (bundle *, int, void *),
			       void *data, uid_t uid);
int app_subapp_terminate_request(void);

int app_com_recv(bundle *b);
int aul_launch_app_with_result_async(const char *appid, bundle *b,
		void (*callback)(bundle *, int, void *), void *data);
int aul_launch_app_with_result_async_for_uid(const char *appid, bundle *b,
		void (*callback)(bundle *, int, void *), void *data, uid_t uid);
int aul_resume_local(void);
int aul_launch_fini(void);
int aul_send_launch_request_for_uid(const char *appid, bundle *b, uid_t uid,
		void (*reply_cb)(bundle *b, int, void *),
		void (*error_cb)(int, void *), void *user_data);
int app_request_local(int cmd, bundle *kb);
