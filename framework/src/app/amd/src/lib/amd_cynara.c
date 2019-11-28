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

#define _GNU_SOURCE
#include <malloc.h>
#include <stdlib.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <glib.h>
#include <glib-unix.h>
#include <aul_sock.h>
#include <aul_svc.h>
#include <aul_svc_priv_key.h>
#include <amd_request.h>
#include <amd_appinfo.h>
#include <aul.h>

#include "amd_cynara.h"
#include "amd_config.h"
#include "amd_util.h"
#include "amd_app_status.h"

static cynara_ops __cynara_ops;
static cynara_caller_info_ops __cynara_ci_ops;
static GList *__pending_checkers;
static GList *__pending_sub_checkers;

struct checker_info {
	const cynara_checker *checkers;
	int cnt;
};

struct sub_checker_info {
	char *name;
	sub_checker_func func;
};

int _cynara_simple_checker(caller_info_h info, request_h req, void *data)
{
	if (__cynara_ops.check)
		return __cynara_ops.check(info, req, data);

	return AMD_CYNARA_ALLOWED;
}

int _cynara_check_privilege(request_h req, cynara_response_cb callback)
{
	if (__cynara_ops.check_async)
		return __cynara_ops.check_async(req, callback);

	return AMD_CYNARA_ALLOWED;
}

int _cynara_check_privilege_offline(request_h req, const char *appid, const char *privilege)
{
	if (__cynara_ops.check_offline)
		return __cynara_ops.check_offline(req, appid, privilege);

	return AMD_CYNARA_ALLOWED;
}

int _cynara_register_checkers(const cynara_checker *checkers, int cnt)
{
	struct checker_info *info;

	if (__cynara_ops.register_checkers)
		return __cynara_ops.register_checkers(checkers, cnt);

	info = calloc(1, sizeof(struct checker_info));
	if (!info) {
		_E("Out-of-memory");
		return -1;
	}

	info->checkers = checkers;
	info->cnt = cnt;
	__pending_checkers = g_list_append(__pending_checkers, info);

	return 0;
}

const char *_cynara_caller_info_get_client(caller_info_h info)
{
	if (__cynara_ci_ops.get_client)
		return __cynara_ci_ops.get_client(info);

	return NULL;
}

int _cynara_sub_checker_add(const char *name, sub_checker_func func)
{
	struct sub_checker_info *sub_info;

	if (__cynara_ops.sub_checker_add)
		return __cynara_ops.sub_checker_add(name, func);

	sub_info = calloc(1, sizeof(struct sub_checker_info));
	if (!sub_info) {
		_E("Out-of-memory");
		return -1;
	}

	sub_info->name = strdup(name);
	sub_info->func = func;

	if (!sub_info->name) {
		_E("Out-of-memory");
		free(sub_info);
		return -1;
	}

	__pending_sub_checkers = g_list_append(__pending_sub_checkers, sub_info);

	return 0;
}

int _cynara_sub_checker_check(const char *name, caller_info_h info, request_h req)
{
	if (__cynara_ops.sub_checker_check)
		return __cynara_ops.sub_checker_check(name, info, req);

	return AMD_CYNARA_CONTINUE;
}

static void __clear_sub_checker_info(gpointer data)
{
	struct sub_checker_info *sub_info = data;

	if (!data)
		return;

	free(sub_info->name);
	free(sub_info);
}

static void __clear_pending_list(void)
{
	if (__pending_checkers) {
		g_list_free_full(__pending_checkers, free);
		__pending_checkers = NULL;
	}

	if (__pending_sub_checkers) {
		g_list_free_full(__pending_sub_checkers, __clear_sub_checker_info);
		__pending_sub_checkers = NULL;
	}
}

int _cynara_register_ops(cynara_ops ops, cynara_caller_info_ops ci_ops)
{
	GList *i = __pending_checkers;
	struct checker_info *info;
	struct sub_checker_info *sub_info;

	__cynara_ops = ops;
	__cynara_ci_ops = ci_ops;
	while (i) {
		info = i->data;
		if (__cynara_ops.register_checkers)
			__cynara_ops.register_checkers(info->checkers, info->cnt);

		i = g_list_next(i);
	}

	i = __pending_sub_checkers;
	while (i) {
		sub_info = i->data;
		if (__cynara_ops.sub_checker_add)
			__cynara_ops.sub_checker_add(sub_info->name, sub_info->func);

		i = g_list_next(i);
	}

	__clear_pending_list();

	return 0;
}

int _cynara_init(void)
{
	_D("cynara init");

	return 0;
}

void _cynara_finish(void)
{
	_D("cynara fini");
	__clear_pending_list();
}

