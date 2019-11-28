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
#include "amd_api_request.h"
#include "amd_request.h"

EXPORT_API int amd_request_send_result(amd_request_h req, int res)
{
	return _request_send_result(req, res);
}

EXPORT_API int amd_request_send_raw(amd_request_h req, int cmd, unsigned char *data, int len)
{
	return _request_send_raw(req, cmd, data, len);
}

EXPORT_API int amd_request_get_fd(amd_request_h req)
{
	return _request_get_fd(req);
}

EXPORT_API int amd_request_get_pid(amd_request_h req)
{
	return _request_get_pid(req);
}

EXPORT_API int amd_request_get_cmd(amd_request_h req)
{
	return _request_get_cmd(req);
}

EXPORT_API int amd_request_set_cmd(amd_request_h req, int cmd)
{
	return _request_set_cmd(req, cmd);
}

EXPORT_API bundle *amd_request_get_bundle(amd_request_h req)
{
	return _request_get_bundle(req);
}

EXPORT_API amd_request_h amd_request_create_local(int cmd, uid_t uid, int pid, bundle *kb)
{
	return _request_create_local(cmd, uid, pid, kb);
}

EXPORT_API void amd_request_free_local(amd_request_h req)
{
	return _request_free_local(req);
}

EXPORT_API int amd_request_remove_fd(amd_request_h req)
{
	return _request_remove_fd(req);
}

EXPORT_API int amd_request_reply_for_pending_request(int pid)
{
	return _request_reply_for_pending_request(pid);
}

EXPORT_API int amd_request_flush_pending_request(int pid)
{
	return _request_flush_pending_request(pid);
}

EXPORT_API uid_t amd_request_get_target_uid(amd_request_h req)
{
	return _request_get_target_uid(req);
}

EXPORT_API uid_t amd_request_get_uid(amd_request_h req)
{
	return _request_get_uid(req);
}

EXPORT_API pid_t amd_request_get_target_pid(amd_request_h req)
{
	return _request_get_target_pid(req);
}

EXPORT_API int amd_request_usr_init(uid_t uid)
{
	return _request_usr_init(uid);
}

EXPORT_API int amd_request_register_cmds(const amd_request_cmd_dispatch *cmds, int cnt)
{
	return _request_register_cmds((request_cmd_dispatch *)cmds, cnt);
}

EXPORT_API int amd_request_reply_append(int pid, void *reply)
{
	return _request_reply_append(pid, reply);
}

EXPORT_API int amd_request_reply_remove(int pid, void *reply)
{
	return _request_reply_remove(pid, reply);
}

EXPORT_API amd_request_reply_h amd_request_reply_create(amd_request_h req,
		pid_t pid, int result, int cmd)
{
	return _request_reply_create(req, pid, result, cmd);
}

EXPORT_API int amd_request_reply_add_extra(amd_request_reply_h handle, const char *key,
		void *extra, void (*extra_free_cb)(void *data))
{
	return _request_reply_add_extra(handle, key, extra, extra_free_cb);
}

EXPORT_API int amd_request_reply_foreach_extra(int pid, int (*callback)(const char *key, void *data))
{
	return _request_reply_foreach_extra(pid, callback);
}

EXPORT_API int amd_request_get_len(amd_request_h req)
{
	return _request_get_len(req);
}

EXPORT_API unsigned char *amd_request_get_raw(amd_request_h req)
{
	return _request_get_raw(req);
}

EXPORT_API GTimeVal *amd_request_get_start_time(amd_request_h req)
{
	return _request_get_start_time(req);
}

EXPORT_API int amd_request_set_request_type(amd_request_h req,
		const char *req_type)
{
	return _request_set_request_type(req, req_type);
}

EXPORT_API const char *amd_request_get_request_type(amd_request_h req)
{
	return _request_get_request_type(req);
}
