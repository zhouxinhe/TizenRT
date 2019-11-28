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

#include <glib.h>
#include <bundle.h>
#include <unistd.h>
#include <sys/types.h>

typedef struct request_s *amd_request_h;
typedef int (*amd_request_cmd_dispatch_cb)(amd_request_h req);
typedef struct _amd_request_cmd_dispatch {
	int cmd;
	amd_request_cmd_dispatch_cb callback;
} amd_request_cmd_dispatch;

typedef void* amd_request_reply_h;

int amd_request_send_result(amd_request_h req, int res);
int amd_request_send_raw(amd_request_h req, int cmd, unsigned char *data, int len);
int amd_request_get_fd(amd_request_h req);
int amd_request_get_pid(amd_request_h req);
int amd_request_get_cmd(amd_request_h req);
int amd_request_set_cmd(amd_request_h req, int cmd);
bundle *amd_request_get_bundle(amd_request_h req);
amd_request_h amd_request_create_local(int cmd, uid_t uid, int pid, bundle *kb);
void amd_request_free_local(amd_request_h req);
int amd_request_remove_fd(amd_request_h req);
int amd_request_reply_for_pending_request(int pid);
int amd_request_flush_pending_request(int pid);
uid_t amd_request_get_target_uid(amd_request_h req);
uid_t amd_request_get_uid(amd_request_h req);
pid_t amd_request_get_target_pid(amd_request_h req);
int amd_request_usr_init(uid_t uid);
int amd_request_register_cmds(const amd_request_cmd_dispatch *cmds, int cnt);
int amd_request_reply_append(int pid, void *reply);
int amd_request_reply_remove(int pid, void *reply);
amd_request_reply_h amd_request_reply_create(amd_request_h req,
		pid_t pid, int result, int cmd);
int amd_request_reply_add_extra(amd_request_reply_h handle, const char *key,
		void *extra, void (*extra_free_cb)(void *data));
int amd_request_reply_foreach_extra(int pid, int (*callback)(const char *key, void *data));
int amd_request_get_len(amd_request_h req);
unsigned char *amd_request_get_raw(amd_request_h req);
GTimeVal *amd_request_get_start_time(amd_request_h req);
int amd_request_set_request_type(amd_request_h req, const char *req_type);
const char *amd_request_get_request_type(amd_request_h req);
