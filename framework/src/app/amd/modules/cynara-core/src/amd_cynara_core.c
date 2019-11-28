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
#include <cynara-client-async.h>
#include <cynara-creds-socket.h>
#include <cynara-session.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <glib.h>
#include <glib-unix.h>
#include <aul_sock.h>
#include <aul_svc.h>
#include <aul_svc_priv_key.h>
#include <aul.h>
#include <amd.h>
#include <security-manager.h>
#include <cert-svc/ccert.h>
#include <cert-svc/cinstance.h>

#include "amd_cynara_core.h"

#define MAX_LOCAL_BUFSZ 128
#define REGULAR_UID_MIN 5000

static cynara_async *r_cynara;
static int cynara_fd = -1;
static guint cynara_fd_id;
static GHashTable *__checker_table;
static GList *__sub_checkers;

struct caller_info {
	GHashTable *id_table;

	char *user;
	char *client;
	char *session;
	char *appid;
	uid_t uid;
	bool offline;

	amd_cynara_response_cb callback;
	void *user_data;
};

typedef struct _cynara_sub_checker {
	char *name;
	amd_cynara_sub_checker_func checker;
} cynara_sub_checker;

static int __check_privilege_offline(const char *appid, const char *privilege,
		uid_t uid);

static gboolean __cancel_func(gpointer key, gpointer value, gpointer user_data)
{
	int r;

	r = cynara_async_cancel_request(r_cynara, GPOINTER_TO_UINT(key));
	if (r != CYNARA_API_SUCCESS)
		_E("cynara_async_cancel_request failed.");

	return TRUE;
}

static void __destroy_caller_info(struct caller_info *info)
{
	if (info == NULL)
		return;

	if (info->appid)
		free(info->appid);

	if (info->client)
		free(info->client);

	if (info->session)
		free(info->session);

	if (info->user)
		free(info->user);

	if (info->id_table) {
		g_hash_table_foreach_remove(info->id_table, __cancel_func, NULL);
		g_hash_table_destroy(info->id_table);
	}

	free(info);
}

static int __get_caller_info_from_cynara(int sockfd, struct caller_info *info)
{
	pid_t pid;
	int r;
	char buf[MAX_LOCAL_BUFSZ];

	if (info == NULL)
		return -1;

	r = cynara_creds_socket_get_pid(sockfd, &pid);
	if (r != CYNARA_API_SUCCESS) {
		cynara_strerror(r, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_creds_socket_get_pid failed: %s", buf);
		return -1;
	}

	info->session = cynara_session_from_pid(pid);
	if (info->session == NULL) {
		_E("cynara_session_from_pid failed.");
		return -1;
	}

	r = cynara_creds_socket_get_user(sockfd, USER_METHOD_DEFAULT,
			&(info->user));
	if (r != CYNARA_API_SUCCESS) {
		cynara_strerror(r, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_cred_socket_get_user failed.");
		return -1;
	}

	r = cynara_creds_socket_get_client(sockfd, CLIENT_METHOD_DEFAULT,
			&(info->client));
	if (r != CYNARA_API_SUCCESS) {
		cynara_strerror(r, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_creds_socket_get_client failed.");
		return -1;
	}

	info->offline = false;

	return 0;
}

static void __resp_cb(cynara_check_id id, cynara_async_call_cause cause,
		int resp, void *data)
{
	enum amd_cynara_result res;
	struct caller_info *info = (struct caller_info *)data;
	char *privilege;

	_D("check id %u, cause %d, resp %d", id, cause, resp);

	privilege = g_hash_table_lookup(info->id_table,
			GUINT_TO_POINTER(id));
	if (privilege == NULL) {
		_W("Cynara: resp: %u not exist in id_table", id);
		return;
	}
	_I("privilege(%s)", privilege);

	g_hash_table_remove(info->id_table, GUINT_TO_POINTER(id));

	switch (cause) {
	case CYNARA_CALL_CAUSE_ANSWER:
		if (resp == CYNARA_API_ACCESS_ALLOWED) {
			if (g_hash_table_size(info->id_table) > 0)
				return;
			res = AMD_CYNARA_RET_ALLOWED;
		} else {
			_E("cynara denied (%s|%s|%s|%d)",
					info->client, info->session,
					info->user, id);
			res = AMD_CYNARA_RET_DENIED;
		}
		break;
	case CYNARA_CALL_CAUSE_CANCEL:
		_D("Cynara: resp: resp %d canceled", id);
		return;
	case CYNARA_CALL_CAUSE_FINISH:
	case CYNARA_CALL_CAUSE_SERVICE_NOT_AVAILABLE:
	default:
		_E("Cynara: resp: not answer");
		res = AMD_CYNARA_RET_ERROR;
		break;
	}

	if (info->callback)
		info->callback(res, info->user_data);

	__destroy_caller_info(info);
}

static enum amd_cynara_result __check_server(struct caller_info *info,
		const char *privilege)
{
	int r;
	cynara_check_id id;

	r = cynara_async_create_request(r_cynara, info->client, info->session,
			info->user, privilege,
			&id, __resp_cb, info);
	if (r != CYNARA_API_SUCCESS) {
		_E("cynara_async_create_request error : %d", r);
		return AMD_CYNARA_RET_ERROR;
	}

	g_hash_table_insert(info->id_table, GUINT_TO_POINTER(id),
			strdup(privilege));

	return AMD_CYNARA_RET_UNKNOWN;
}

static enum amd_cynara_result __check_cache(struct caller_info *info,
		const char *privilege)
{
	int ret;

	ret = cynara_async_check_cache(r_cynara, info->client, info->session,
			info->user, privilege);
	switch (ret) {
	case CYNARA_API_ACCESS_ALLOWED:
		ret = AMD_CYNARA_RET_ALLOWED;
		break;
	case CYNARA_API_ACCESS_DENIED:
		ret = AMD_CYNARA_RET_DENIED;
		break;
	case CYNARA_API_CACHE_MISS:
		ret = AMD_CYNARA_RET_UNKNOWN;
		break;
	default:
		_E("cynara cache error %d (%s|%s|%s)", ret,
				info->client, info->session, info->user);
		ret = AMD_CYNARA_RET_UNKNOWN;
		break;
	}

	return ret;
}

static int __cynara_simple_checker(amd_cynara_caller_info_h info, amd_request_h req, void *data)
{
	int ret;
	const char *privilege = data;

	if (info->offline) {
		ret = __check_privilege_offline(info->appid, privilege,
				info->uid);
	} else {
		ret = __check_cache(info, privilege);
	}
	if (ret != AMD_CYNARA_RET_UNKNOWN) {
		if (ret == AMD_CYNARA_RET_DENIED) {
			_E("cynara denied (%s|%s|%s|%s)", privilege,
					info->client, info->session, info->user);
		}
		return ret;
	}

	return __check_server(info, privilege);
}

static int __check_privilege_by_checker(amd_request_h req, amd_cynara_caller_info_h info)
{
	int ret;
	amd_cynara_checker *checker;

	checker = g_hash_table_lookup(__checker_table,
			GINT_TO_POINTER(amd_request_get_cmd(req)));
	if (checker && checker->checker) {
		ret = checker->checker(info, req, checker->data);
		return ret;
	}

	return 0;
}

static bool __has_checker(amd_request_h req)
{
	amd_cynara_checker *checker;

	checker = g_hash_table_lookup(__checker_table,
			GINT_TO_POINTER(amd_request_get_cmd(req)));
	if (checker)
		return true;

	return false;
}

static bool __has_platform_cert(const char *appid, uid_t uid)
{
	amd_appinfo_h ai;
	const char *pkgid;
	const char *visibility_str;
	int visibility;
	char buf[12];

	ai = amd_appinfo_find(uid, appid);
	if (!ai)
		return false;

	visibility_str = amd_appinfo_get_value(ai, AMD_AIT_VISIBILITY);
	if (!visibility_str) {
		pkgid = amd_appinfo_get_value(ai, AMD_AIT_PKGID);
		visibility = amd_appinfo_get_cert_visibility(pkgid, uid);
		snprintf(buf, sizeof(buf), "%d", visibility);
		amd_appinfo_set_value(ai, AMD_AIT_VISIBILITY, buf);
		visibility_str = buf;
	}

	visibility = atoi(visibility_str);
	if (visibility & CERTSVC_VISIBILITY_PLATFORM)
		return true;

	return false;
}

static int __verify_caller_process(amd_request_h req)
{
	amd_app_status_h app_status;
	const char *appid;
	pid_t pid;
	uid_t uid;
	char attr[512] = { 0, };
	int r;

	uid = amd_request_get_uid(req);
	if (uid < REGULAR_UID_MIN)
		return 0;

	pid = amd_request_get_pid(req);
	app_status = amd_app_status_find_by_effective_pid(pid);
	if (app_status) {
		appid = amd_app_status_get_appid(app_status);
		if (__has_platform_cert(appid, uid))
			return 0;
	} else {
		r = amd_proc_get_attr(pid, attr, sizeof(attr));
		if (r != 0) {
			_E("Failed to get attr. pid(%d)", pid);
			return -1;
		}

		if (!strcmp(attr, "User"))
			return 0;
	}

	_E("Reject request. caller(%d)", pid);

	return -1;
}

static bool __is_indirect_request(amd_request_h req)
{
	const char *req_type;

	req_type = amd_request_get_request_type(req);
	if (req_type && !strcmp(req_type, "indirect-request"))
		return true;

	return false;
}

static int __check_org_caller(bundle *b,
		const char *org_caller_appid, uid_t org_caller_uid)
{
	amd_appinfo_h appinfo;
	const char *org_caller_pkgid;
	const char *pkgid;

	appinfo = amd_appinfo_find(org_caller_uid, org_caller_appid);
	if (!appinfo) {
		_E("Failed to find appinfo(%s:%u)",
				org_caller_appid, org_caller_uid);
		return -1;
	}

	pkgid = amd_appinfo_get_value(appinfo, AMD_AIT_PKGID);
	if (!pkgid) {
		_E("Critical error!");
		return -1;
	}

	org_caller_pkgid = bundle_get_val(b, AUL_K_ORG_CALLER_PKGID);
	if (!org_caller_pkgid) {
		_E("Failed to get pkgid");
		return -1;
	}

	if (strcmp(pkgid, org_caller_pkgid) != 0) {
		_E("%s is not equal to %s", org_caller_pkgid, pkgid);
		return -1;
	}

	return 0;
}

static int __get_org_caller_info_from_bundle(bundle *b,
		struct caller_info *info)
{
	int r;
	const char *str;

	str = bundle_get_val(b, AUL_K_ORG_CALLER_APPID);
	if (!str) {
		_E("Failed to get org caller appid");
		return -1;
	}

	info->appid = strdup(str);
	if (!info->appid) {
		_E("Out of memory");
		return -1;
	}

	str = bundle_get_val(b, AUL_K_ORG_CALLER_UID);
	if (!str) {
		_E("Failed to get org caller uid");
		return -1;
	}

	info->uid = strtoul(str, NULL, 10);

	r = __check_org_caller(b, info->appid, info->uid);
	if (r < 0)
		return -1;

	info->offline = true;
	_D("Orginal caller(%s:%u)", info->appid, info->uid);

	return 0;
}

static struct caller_info *__create_caller_info(amd_request_h req,
		amd_cynara_response_cb callback)
{
	int r;
	struct caller_info *info;
	bundle *b;

	info = calloc(1, sizeof(*info));
	if (info == NULL) {
		_E("insufficient memory");
		return NULL;
	}

	if (__is_indirect_request(req)) {
		b = amd_request_get_bundle(req);
		if (!b) {
			_E("Failed to get bundle");
			__destroy_caller_info(info);
			return NULL;
		}

		r = __get_org_caller_info_from_bundle(b, info);
		if (r < 0) {
			_E("Failed to get org caller info");
			__destroy_caller_info(info);
			return NULL;
		}
	} else {
		r = __get_caller_info_from_cynara(amd_request_get_fd(req),
				info);
		if (r < 0) {
			_E("Failed to get caller info");
			__destroy_caller_info(info);
			return NULL;
		}
	}

	info->callback = callback;
	info->user_data = req;

	info->id_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
			NULL, free);

	return info;
}

static int __cynara_check_privilege(amd_request_h req, amd_cynara_response_cb callback)
{
	int r;
	struct caller_info *info;

	if (!__has_checker(req)) {
		_D("No proper checker. Skip checking privileges (cmd = %d)",
				amd_request_get_cmd(req));
		return AMD_CYNARA_RET_ALLOWED;
	}

	if (__is_indirect_request(req)) {
		r = __verify_caller_process(req);
		if (r != 0)
			return AMD_CYNARA_RET_DENIED;
	}

	info = __create_caller_info(req, callback);
	if (info == NULL)
		return -1;

	r = __check_privilege_by_checker(req, info);

	if (r != AMD_CYNARA_RET_UNKNOWN)
		__destroy_caller_info(info);

	return r;
}

static int __check_privilege_offline(const char *appid, const char *privilege,
		uid_t uid)
{
	int priv_ret;
	int ret;

	ret = security_manager_app_has_privilege(appid, privilege,
			uid, &priv_ret);
	if (ret < 0) {
		_E("failed to check privilege (%d)", ret);
		return AMD_CYNARA_RET_DENIED;
	}

	if (priv_ret != 1)
		return AMD_CYNARA_RET_DENIED;

	return AMD_CYNARA_RET_ALLOWED;
}

static int __cynara_check_privilege_offline(amd_request_h req,
		const char *appid, const char *privilege)
{
	return __check_privilege_offline(appid, privilege,
			amd_request_get_target_uid(req));
}

static gboolean __proc_cb(gint fd, GIOCondition cond, gpointer data)
{
	int ret;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		cynara_fd_id = 0;
		return G_SOURCE_REMOVE;
	}

	ret = cynara_async_process(r_cynara);
	if (ret != CYNARA_API_SUCCESS)
		_E("process error %d", ret);

	return G_SOURCE_CONTINUE;
}

static void __status_cb(int old_fd, int new_fd, cynara_async_status status,
		void *data)
{
	if (old_fd != -1) {
		if (cynara_fd_id) {
			g_source_remove(cynara_fd_id);
			cynara_fd_id = 0;
		}
		cynara_fd = -1;
	}

	if (new_fd != -1) {
		GIOCondition cond;

		cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;

		if (status == CYNARA_STATUS_FOR_RW)
			cond |= G_IO_OUT;

		cynara_fd_id = g_unix_fd_add(new_fd, cond, __proc_cb, data);
		cynara_fd = new_fd;
	}
}

static int __cynara_register_checkers(const amd_cynara_checker *checkers, int cnt)
{
	int i;
	amd_cynara_checker *c;

	if (cnt <= 0 || !__checker_table || !checkers)
		return -1;

	for (i = 0; i < cnt; i++) {
		c = g_hash_table_lookup(__checker_table,
			GINT_TO_POINTER(checkers[i].cmd));
		if (c) {
			if (checkers[i].priority <= c->priority)
				continue;

			g_hash_table_remove(__checker_table,
				GINT_TO_POINTER(checkers[i].cmd));
		}

		g_hash_table_insert(__checker_table,
				GINT_TO_POINTER(checkers[i].cmd),
				(gpointer)(&checkers[i]));
	}

	return 0;
}

static const char *__cynara_caller_info_get_client(amd_cynara_caller_info_h info)
{
	if (!info)
		return NULL;

	return info->client;
}

static int __cynara_sub_checker_add(const char *name, amd_cynara_sub_checker_func func)
{
	cynara_sub_checker *c;

	if (!name || !func)
		return -1;

	c = calloc(1, sizeof(cynara_sub_checker));
	if (!c)
		return -1;

	c->name = strdup(name);
	c->checker = func;

	if (!(c->name)) {
		free(c);
		return -1;
	}

	__sub_checkers = g_list_append(__sub_checkers, c);

	return 0;
}

static int __cynara_sub_checker_check(const char *name, amd_cynara_caller_info_h info, amd_request_h req)
{
	GList *i = __sub_checkers;
	cynara_sub_checker *c;
	int ret;

	if (!name || !info || !req)
		return AMD_CYNARA_RET_ERROR;

	while (i) {
		c = i->data;
		if (!strcmp(name, c->name)) {
			ret = c->checker(info, req);
			if (ret != AMD_CYNARA_RET_CONTINUE)
				return ret;
		}

		i = g_list_next(i);
	}

	return AMD_CYNARA_RET_CONTINUE;
}

EXPORT int AMD_MOD_INIT(void)
{
	int ret;

	_D("Cynara-core init");
	ret = cynara_async_initialize(&r_cynara, NULL, __status_cb, NULL);
	if (ret != CYNARA_API_SUCCESS) {
		_E("cynara initialize failed. %d", ret);
		return ret;
	}

	__checker_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
			NULL, NULL);

	amd_cynara_ops ops = {
		.register_checkers = __cynara_register_checkers,
		.sub_checker_add = __cynara_sub_checker_add,
		.sub_checker_check = __cynara_sub_checker_check,
		.check_async = __cynara_check_privilege,
		.check = __cynara_simple_checker,
		.check_offline = __cynara_check_privilege_offline
	};

	amd_cynara_caller_info_ops ci_ops = {
		.get_client = __cynara_caller_info_get_client
	};

	return amd_cynara_register_ops(ops, ci_ops);
}

static void __free_sub_checker(gpointer data)
{
	cynara_sub_checker *c = data;

	free(c->name);
	free(c);
}

EXPORT void AMD_MOD_FINI(void)
{
	_D("Cynara-core fini");
	if (r_cynara == NULL)
		return;

	if (cynara_fd_id) {
		g_source_remove(cynara_fd_id);
		cynara_fd_id = 0;
	}

	cynara_async_finish(r_cynara);
	r_cynara = NULL;
	cynara_fd = -1;

	if (__checker_table) {
		g_hash_table_destroy(__checker_table);
		__checker_table = NULL;
	}

	if (__sub_checkers) {
		g_list_free_full(__sub_checkers, __free_sub_checker);
		__sub_checkers = NULL;
	}
}


