/*
 * Copyright (c) 2015 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
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

typedef struct request_s *request_h;
typedef int (*request_cmd_dispatch_cb)(request_h req);
typedef struct _request_cmd_dispatch {
	int cmd;
	request_cmd_dispatch_cb callback;
} request_cmd_dispatch;

typedef void* request_reply_h;

int _request_send_result(request_h req, int res);
int _request_send_raw(request_h req, int cmd, unsigned char *data, int len);
int _request_get_fd(request_h req);
int _request_get_pid(request_h req);
int _request_get_cmd(request_h req);
int _request_set_cmd(request_h req, int cmd);
bundle *_request_get_bundle(request_h req);
request_h _request_create_local(int cmd, uid_t uid, int pid, bundle *kb);
void _request_free_local(request_h req);
int _request_remove_fd(request_h req);
int _request_reply_for_pending_request(int pid);
int _request_flush_pending_request(int pid);
uid_t _request_get_target_uid(request_h req);
uid_t _request_get_uid(request_h req);
pid_t _request_get_target_pid(request_h req);
int _request_usr_init(uid_t uid);
int _request_register_cmds(const request_cmd_dispatch *cmds, int cnt);
int _request_init(void);
void _request_fini(void);
int _request_reply_reset_pending_timer(request_h req, unsigned int interval, int pid);
int _request_reply_append(int pid, void *reply);
int _request_reply_remove(int pid, void *reply);
request_reply_h _request_reply_create(request_h req, pid_t pid, int result, int cmd);
int _request_reply_add_extra(request_reply_h handle, const char *key,
		void *extra, void (*extra_free_cb)(void *data));
int _request_reply_foreach_extra(int pid, int (*callback)(const char *key, void *data));
int _request_get_len(request_h req);
unsigned char *_request_get_raw(request_h req);
GTimeVal *_request_get_start_time(request_h req);
int _request_set_request_type(request_h req, const char *req_type);
const char *_request_get_request_type(request_h req);
