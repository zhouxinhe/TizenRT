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
#include "amd_api_cynara.h"
#include "amd_cynara.h"

static cynara_ops __ops;
static cynara_caller_info_ops __ci_ops;
static amd_cynara_ops __amd_ops;
static amd_cynara_caller_info_ops __amd_ci_ops;

EXPORT_API int amd_cynara_check_privilege(amd_request_h req,
		amd_cynara_response_cb callback)
{
	return _cynara_check_privilege(req, (cynara_response_cb)callback);
}

EXPORT_API int amd_cynara_check_privilege_offline(amd_request_h req,
		const char *appid, const char *privilege)
{
	return _cynara_check_privilege_offline(req, appid, privilege);
}

EXPORT_API int amd_cynara_register_checkers(const amd_cynara_checker *checkers,
		int cnt)
{
	return _cynara_register_checkers((cynara_checker *)checkers, cnt);
}

EXPORT_API int amd_cynara_simple_checker(amd_cynara_caller_info_h info,
		amd_request_h req, void *data)
{
	return _cynara_simple_checker(info, req, data);
}

EXPORT_API const char *amd_cynara_caller_info_get_client(
		amd_cynara_caller_info_h info)
{
	return _cynara_caller_info_get_client(info);
}

EXPORT_API int amd_cynara_sub_checker_add(const char *name,
		amd_cynara_sub_checker_func func)
{
	return _cynara_sub_checker_add(name, func);
}

EXPORT_API int amd_cynara_sub_checker_check(const char *name,
		amd_cynara_caller_info_h info, amd_request_h req)
{
	return _cynara_sub_checker_check(name, info, req);
}

static int __register_checkers(const cynara_checker *checkers, int cnt)
{
	return __amd_ops.register_checkers((amd_cynara_checker *)checkers, cnt);
}

static int __sub_checker_add(const char *name, sub_checker_func func)
{
	return __amd_ops.sub_checker_add(name, func);
}

static int __sub_checker_check(const char *name, caller_info_h info, request_h req)
{
	return __amd_ops.sub_checker_check(name, info, req);
}

static int __check_async(request_h req, cynara_response_cb callback)
{
	return __amd_ops.check_async(req, (amd_cynara_response_cb)callback);
}

static int __check(caller_info_h info, request_h req, void *data)
{
	return __amd_ops.check(info, req, data);
}

static int __check_offline(request_h req, const char *appid, const char *privilege)
{
	return __amd_ops.check_offline(req, appid, privilege);
}

static const char *__get_client(caller_info_h info)
{
	return __amd_ci_ops.get_client(info);
}

EXPORT_API int amd_cynara_register_ops(amd_cynara_ops ops,
		amd_cynara_caller_info_ops ci_ops)
{
	__amd_ops = ops;
	__amd_ci_ops = ci_ops;

	__ops.register_checkers = __register_checkers;
	__ops.sub_checker_add = __sub_checker_add;
	__ops.sub_checker_check = __sub_checker_check;
	__ops.check_async  = __check_async;
	__ops.check = __check;
	__ops.check_offline = __check_offline;
	__ci_ops.get_client = __get_client;

	return _cynara_register_ops(__ops, __ci_ops);
}

