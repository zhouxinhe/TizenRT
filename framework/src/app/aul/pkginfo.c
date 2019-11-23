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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <bundle_internal.h>

#include "aul.h"
#include "aul_api.h"
#include "menu_db_util.h"
#include "aul_sock.h"
#include "aul_util.h"
#include "aul_proc.h"
#include "aul_error.h"

typedef struct _internal_param_t {
	aul_app_info_iter_fn iter_fn;
	void *user_data;
} internal_param_t;

static const char *__appid;
static const char *__pkgid;
static const char *__root_path;

API int aul_app_get_pid(const char *appid)
{
	return aul_app_get_pid_for_uid(appid, getuid());
}

API int aul_app_get_pid_for_uid(const char *appid, uid_t uid)
{
	int ret;
	char buf[MAX_PID_STR_BUFSZ];
	bundle *b;

	if (appid == NULL)
		return -1;

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return -1;
	}

	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_add(b, AUL_K_APPID, appid);
	bundle_add(b, AUL_K_TARGET_UID, buf);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, uid, APP_GET_PID,
			b, AUL_SOCK_NONE);
	bundle_free(b);

	return ret;
}

API int aul_app_is_running(const char *appid)
{
	return aul_app_is_running_for_uid(appid, getuid());
}

API int aul_app_is_running_for_uid(const char *appid, uid_t uid)
{
	int ret;
	char buf[MAX_PID_STR_BUFSZ];
	bundle *b;

	if (appid == NULL)
		return 0;

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return 0;
	}

	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_add(b, AUL_K_APPID, appid);
	bundle_add(b, AUL_K_TARGET_UID, buf);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, uid, APP_IS_RUNNING,
			b, AUL_SOCK_NONE);
	bundle_free(b);
	if (ret > 0)
		return true;

	return 0;
}

static void __running_app_info_cb(app_pkt_t *pkt, void *user_data)
{
	internal_param_t *param = (internal_param_t *)user_data;
	bundle *b = NULL;
	aul_app_info info;
	const char *val;

	if (pkt == NULL || param == NULL) {
		_E("Invalid parameter");
		return;
	}

	if (pkt->cmd == APP_GET_INFO_ERROR) {
		_E("Failed to get app info");
		return;
	}

	if (pkt->opt & AUL_SOCK_BUNDLE)
		b = bundle_decode(pkt->data, pkt->len);

	if (b == NULL)
		return;

	val = bundle_get_val(b, AUL_K_PID);
	if (val == NULL) {
		bundle_free(b);
		return;
	}
	info.pid = atoi(val);

	info.appid = (char *)bundle_get_val(b, AUL_K_APPID);
	info.app_path = (char *)bundle_get_val(b, AUL_K_EXEC);
	info.pkgid = (char *)bundle_get_val(b, AUL_K_PKGID);
	info.instance_id = (char *)bundle_get_val(b, AUL_K_INSTANCE_ID);

	val = bundle_get_val(b, AUL_K_STATUS);
	if (val == NULL) {
		bundle_free(b);
		return;
	}
	info.status = atoi(val);

	val = bundle_get_val(b, AUL_K_IS_SUBAPP);
	if (val == NULL) {
		bundle_free(b);
		return;
	}
	info.is_sub_app = atoi(val);

	info.pkg_name = info.appid;
	param->iter_fn(&info, param->user_data);
	bundle_free(b);
}

static int __get_running_app_info(int cmd, aul_app_info_iter_fn iter_fn,
		void *user_data, uid_t uid)
{
	int ret;
	int fd;
	bundle *b;
	char buf[MAX_PID_STR_BUFSZ];
	internal_param_t param = {iter_fn, user_data};

	if (iter_fn == NULL)
		return AUL_R_EINVAL;

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_add(b, AUL_K_TARGET_UID, buf);

	fd = aul_sock_send_bundle(AUL_UTIL_PID, uid, cmd, b, AUL_SOCK_ASYNC);
	bundle_free(b);
	if (fd < 0)
		return aul_error_convert(fd);

	ret = aul_sock_recv_pkt_with_cb(fd, __running_app_info_cb, &param);
	if (ret < 0)
		return aul_error_convert(ret);

	return AUL_R_OK;
}

API int aul_app_get_running_app_info(aul_app_info_iter_fn iter_fn,
		void *user_data)
{
	return aul_app_get_running_app_info_for_uid(iter_fn,
			user_data, getuid());
}

API int aul_app_get_running_app_info_for_uid(aul_app_info_iter_fn iter_fn,
		void *user_data, uid_t uid)
{
	return __get_running_app_info(APP_RUNNING_INFO, iter_fn,
			user_data, uid);
}

API int aul_app_get_all_running_app_info(aul_app_info_iter_fn iter_fn,
		void *user_data)
{
	return aul_app_get_all_running_app_info_for_uid(iter_fn,
			user_data, getuid());
}

API int aul_app_get_all_running_app_info_for_uid(aul_app_info_iter_fn iter_fn,
		void *user_data, uid_t uid)
{
	return __get_running_app_info(APP_ALL_RUNNING_INFO, iter_fn,
			user_data, uid);
}

API int aul_app_get_running_app_instance_info(aul_app_info_iter_fn iter_fn,
		void *user_data)
{
	return aul_app_get_running_app_instance_info_for_uid(iter_fn,
			user_data, getuid());
}

API int aul_app_get_running_app_instance_info_for_uid(
		aul_app_info_iter_fn iter_fn, void *user_data, uid_t uid)
{
	return __get_running_app_info(APP_RUNNING_INSTANCE_INFO, iter_fn,
			user_data, uid);
}

API void aul_set_preinit_appid(const char *appid)
{
	__appid = appid;
}

const char *__get_preinit_appid(void)
{
	if (!__appid)
		__appid = getenv("AUL_APPID");

	return __appid;
}

API void aul_set_preinit_pkgid(const char *pkgid)
{
	__pkgid = pkgid;
}

const char *__get_preinit_pkgid(void)
{
	if (!__pkgid)
		__pkgid = getenv("AUL_PKGID");

	return __pkgid;
}

API void aul_set_preinit_root_path(const char *root_path)
{
	__root_path = root_path;
}

API const char *aul_get_preinit_root_path(void)
{
	if (!__root_path)
		__root_path = getenv("AUL_ROOT_PATH");

	return __root_path;
}

API int aul_app_get_pkgname_bypid(int pid, char *pkgname, int len)
{
	return aul_app_get_appid_bypid(pid, pkgname, len);
}

API int aul_app_get_appid_bypid_for_uid(int pid, char *appid, int len,
		uid_t uid)
{
	app_pkt_t *pkt = NULL;
	int fd;
	int ret;
	const char *preinit_appid;
	bundle *b;
	char buf[MAX_PID_STR_BUFSZ];

	if (pid <= 0 || appid == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	if (getpid() == pid) {
		preinit_appid = __get_preinit_appid();
		if (preinit_appid) {
			snprintf(appid, len, "%s", preinit_appid);
			return AUL_R_OK;
		}
	}

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%d", pid);
	bundle_add(b, AUL_K_PID, buf);
	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_add(b, AUL_K_TARGET_UID, buf);

	fd = aul_sock_send_bundle(AUL_UTIL_PID, uid, APP_GET_APPID_BYPID,
			b, AUL_SOCK_ASYNC);
	bundle_free(b);
	if (fd <= 0)
		return AUL_R_ERROR;

	ret = aul_sock_recv_reply_pkt(fd, &pkt);
	if (ret < 0 || pkt == NULL)
		return AUL_R_ERROR;

	if (pkt->cmd == APP_GET_INFO_OK) {
		snprintf(appid, len, "%s", pkt->data);
		free(pkt);
		return AUL_R_OK;
	}
	free(pkt);

	return AUL_R_ERROR;
}

API int aul_app_get_appid_bypid(int pid, char *appid, int len)
{
	return aul_app_get_appid_bypid_for_uid(pid, appid, len, getuid());
}

static int __get_pkginfo(int pid, char *buf, int len, uid_t uid)
{
	const char *appid;
	app_info_from_db *menu_info;

	appid = __get_preinit_appid();
	if (appid == NULL) {
		_E("Failed to get preinit appid - %d", pid);
		return -1;
	}

	menu_info = _get_app_info_from_db_by_appid_user(appid, uid);
	if (menu_info == NULL) {
		_E("Failed to get app info - %s", appid);
		return -1;
	}

	snprintf(buf, len, "%s", _get_pkgid(menu_info));
	_free_app_info_from_db(menu_info);

	return 0;
}

API int aul_app_get_pkgid_bypid_for_uid(int pid, char *pkgid, int len,
		uid_t uid)
{
	app_pkt_t *pkt = NULL;
	int fd;
	int ret;
	const char *preinit_pkgid;
	bundle *b;
	char buf[MAX_PID_STR_BUFSZ];

	if (pid <= 0 || pkgid == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	if (getpid() == pid) {
		preinit_pkgid = __get_preinit_pkgid();
		if (preinit_pkgid) {
			snprintf(pkgid, len, "%s", preinit_pkgid);
			return AUL_R_OK;
		} else {
			/* fallback (for debugging) */
			ret = __get_pkginfo(pid, pkgid, len, uid);
			if (ret == 0)
				return AUL_R_OK;
		}
	}

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%d", pid);
	bundle_add(b, AUL_K_PID, buf);
	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_add(b, AUL_K_TARGET_UID, buf);

	fd = aul_sock_send_bundle(AUL_UTIL_PID, uid, APP_GET_PKGID_BYPID,
			b, AUL_SOCK_ASYNC);
	bundle_free(b);
	if (fd <= 0)
		return AUL_R_ERROR;

	ret = aul_sock_recv_reply_pkt(fd, &pkt);
	if (ret < 0 || pkt == NULL)
		return AUL_R_ERROR;

	if (pkt->cmd == APP_GET_INFO_OK) {
		snprintf(pkgid, len, "%s", pkt->data);
		free(pkt);
		return AUL_R_OK;
	}
	free(pkt);

	return AUL_R_ERROR;
}

API int aul_app_get_pkgid_bypid(int pid, char *pkgid, int len)
{
	return aul_app_get_pkgid_bypid_for_uid(pid, pkgid, len, getuid());
}

API int aul_update_rua_stat_for_uid(bundle *b, uid_t uid)
{
	int ret;
	char buf[MAX_PID_STR_BUFSZ];

	if (b == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_del(b, AUL_K_TARGET_UID);
	bundle_add(b, AUL_K_TARGET_UID, buf);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, uid,
			APP_UPDATE_RUA_STAT, b, AUL_SOCK_NONE);
	return ret;
}

API int aul_add_rua_history_for_uid(bundle *b, uid_t uid)
{
	int ret;
	char buf[MAX_PID_STR_BUFSZ];

	if (b == NULL) {
		SECURE_LOGE("invalid param");
		return AUL_R_EINVAL;
	}

	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_del(b, AUL_K_TARGET_UID);
	bundle_add(b, AUL_K_TARGET_UID, buf);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, uid,
			APP_ADD_HISTORY, b, AUL_SOCK_NONE);
	return ret;
}

API int aul_delete_rua_history_for_uid(bundle *b, uid_t uid)
{
	int ret;
	char buf[MAX_PID_STR_BUFSZ];
	bundle *kb = NULL;

	if (b == NULL) {
		kb = bundle_create();
		if (kb == NULL) {
			_E("out of memory");
			return AUL_R_ERROR;
		}

		b = kb;
	}

	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_del(b, AUL_K_TARGET_UID);
	bundle_add(b, AUL_K_TARGET_UID, buf);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, uid, APP_REMOVE_HISTORY,
			b, AUL_SOCK_NONE);
	if (kb)
		bundle_free(kb);

	return ret;
}

API int aul_set_default_app_by_operation(bundle *b)
{
	int ret;

	if (b == NULL)
		return AUL_R_EINVAL;

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			APP_SET_APP_CONTROL_DEFAULT_APP, b, AUL_SOCK_NONE);
	if (ret != 0) {
		if (ret == -EILLEGALACCESS)
			return AUL_R_EILLACC;
		else
			return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_unset_default_app_by_operation(const char *app_id)
{
	int ret;

	if (app_id == NULL)
		return AUL_R_EINVAL;

	ret = aul_sock_send_raw(AUL_UTIL_PID, getuid(), APP_UNSET_APP_CONTROL_DEFAULT_APP,
			(unsigned char *)app_id, strlen(app_id), AUL_SOCK_NONE);
	if (ret != 0) {
		if (ret == -EILLEGALACCESS)
			return AUL_R_EILLACC;
		else
			return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_app_get_last_caller_pid(int pid)
{
	return aul_app_get_last_caller_pid_for_uid(pid, getuid());
}

API int aul_app_get_last_caller_pid_for_uid(int pid, uid_t uid)
{
	int ret;
	char buf[MAX_PID_STR_BUFSZ];
	bundle *b;

	if (pid < 0) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	b = bundle_create();
	if (b == NULL) {
		_E("Failed to create bundle");
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%d", pid);
	bundle_add(b, AUL_K_PID, buf);
	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_add(b, AUL_K_TARGET_UID, buf);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, uid, APP_GET_LAST_CALLER_PID,
			b, AUL_SOCK_NONE);
	bundle_free(b);
	if (ret < 0)
		return aul_error_convert(ret);

	return ret;
}

API int aul_set_alias_appid(const char *alias_appid, const char *appid)
{
	int ret;
	bundle *b;

	if (alias_appid == NULL || appid == NULL) {
		_E("Invalid parameters");
		return AUL_R_EINVAL;
	}

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}
	bundle_add(b, AUL_K_ALIAS_APPID, alias_appid);
	bundle_add(b, AUL_K_APPID, appid);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			APP_SET_ALIAS_APPID, b, AUL_SOCK_NONE);
	bundle_free(b);
	if (ret != AUL_R_OK)
		return aul_error_convert(ret);

	return AUL_R_OK;
}

API int aul_unset_alias_appid(const char *alias_appid)
{
	int ret;
	bundle *b;

	if (alias_appid == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}
	bundle_add(b, AUL_K_ALIAS_APPID, alias_appid);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			APP_UNSET_ALIAS_APPID, b, AUL_SOCK_NONE);
	bundle_free(b);
	if (ret != AUL_R_OK)
		return aul_error_convert(ret);

	return AUL_R_OK;
}

API int aul_enable_alias_info(const char *appid)
{
	int ret;
	bundle *b;

	if (appid == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}
	bundle_add(b, AUL_K_APPID, appid);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			APP_ENABLE_ALIAS_INFO, b, AUL_SOCK_NONE);
	bundle_free(b);
	if (ret != AUL_R_OK)
		return aul_error_convert(ret);

	return AUL_R_OK;
}

API int aul_disable_alias_info(const char *appid)
{
	int ret;
	bundle *b;

	if (appid == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}
	bundle_add(b, AUL_K_APPID, appid);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			APP_DISABLE_ALIAS_INFO, b, AUL_SOCK_NONE);
	bundle_free(b);
	if (ret != AUL_R_OK)
		return aul_error_convert(ret);

	return AUL_R_OK;
}

API int aul_app_get_instance_id_bypid_for_uid(int pid, char *instance_id,
		int len, uid_t uid)
{
	app_pkt_t *pkt = NULL;
	bundle *b;
	int ret;
	int fd;
	char buf[MAX_PID_STR_BUFSZ];

	if (pid <= 0 || instance_id == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	b = bundle_create();
	if (b == NULL) {
		_E("Out of memory");
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%d", pid);
	bundle_add(b, AUL_K_PID, buf);
	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_add(b, AUL_K_TARGET_UID, buf);

	fd = aul_sock_send_bundle(AUL_UTIL_PID, uid,
			APP_GET_INSTANCE_ID_BYPID, b,
			AUL_SOCK_ASYNC);
	bundle_free(b);
	if (fd <= 0)
		return AUL_R_ERROR;

	ret = aul_sock_recv_reply_pkt(fd, &pkt);
	if (ret < 0 || pkt == NULL)
		return  AUL_R_ERROR;

	if (pkt->cmd == APP_GET_INFO_OK) {
		snprintf(instance_id, len, "%s", pkt->data);
		free(pkt);
		return AUL_R_OK;
	}

	free(pkt);

	return AUL_R_ERROR;
}

API int aul_app_get_instance_id_bypid(int pid, char *instance_id, int len)
{
	return aul_app_get_instance_id_bypid_for_uid(pid,
			instance_id, len, getuid());
}
