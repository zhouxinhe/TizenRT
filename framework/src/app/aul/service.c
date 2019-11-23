/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <glib.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <iniparser.h>
#include <pkgmgr-info.h>

#include "aul.h"
#include "aul_api.h"
#include "aul_svc.h"
#include "aul_sock.h"
#include "aul_svc_db.h"
#include "aul_util.h"
#include "aul_svc_priv_key.h"
#include "launch.h"

#define MAX_CHECKSUM_BUF	2048

/* callback handling */
typedef struct _aul_svc_cb_info_t {
	int request_code;
	aul_svc_res_fn cb_func;
	aul_svc_err_cb err_cb;
	void *data;
} aul_svc_cb_info_t;

typedef struct _aul_svc_resolve_info_t {
	char *pkgname;
	char *op;
	char *uri;
	char *scheme;
	char *host;
	char *uri_r_info;
	char *origin_mime;
	char *mime;
	char *m_type;
	char *s_type;
	char *category;
	char *win_id;
	int mime_set;
} aul_svc_resolve_info_t;

typedef struct _aul_svc_transient_cb_info_t {
	aul_svc_host_res_fn cb_func;
	void *data;
} aul_svc_transient_cb_info_t;

pthread_mutex_t iniparser_lock = PTHREAD_MUTEX_INITIALIZER;
GSList *tmp_list;

static aul_svc_cb_info_t *__create_rescb(int request_code,
		aul_svc_res_fn cbfunc, aul_svc_err_cb err_cb, void *data);
static void __remove_rescb(aul_svc_cb_info_t *info);
static int __set_bundle(bundle *b, const char *key, const char *value);
static void __aul_cb(bundle *b, int is_cancel, void *data);
static int __run_svc_with_pkgname(char *pkgname, bundle *b, int request_code,
		aul_svc_res_fn cbfunc, aul_svc_err_cb err_cb, void *data,
		uid_t uid, bool sync);
static int __get_resolve_info(bundle *b, aul_svc_resolve_info_t *info);
static int __free_resolve_info_data(aul_svc_resolve_info_t *info);

static char *white_list[] = {
	APP_SELECTOR,
	SHARE_PANEL,
	NULL
};

static bool __is_special_app(const char *appid)
{
	const char *id;
	int i = 0;

	if (appid == NULL)
		return false;

	while ((id = white_list[i]) != NULL) {
		if (strcmp(id, appid) == 0)
			return true;
		i++;
	}
	return false;
}

static bool __is_special_operation(bundle *b)
{
	const char *operation;
	const char *white_operations[] = {
		"http://tizen.org/appcontrol/operation/guide_privacy_setting",
		NULL
	};
	int i;

	operation = aul_svc_get_operation(b);
	if (!operation)
		return false;

	for (i = 0; white_operations[i]; ++i) {
		if (!strcmp(operation, white_operations[i]))
			return true;
	}

	return false;
}

static aul_svc_cb_info_t *__create_rescb(int request_code,
		aul_svc_res_fn cbfunc, aul_svc_err_cb err_cb, void *data)
{
	aul_svc_cb_info_t* info;

	info = calloc(1, sizeof(aul_svc_cb_info_t));
	if (info == NULL) {
		_E("Out of memory");
		return NULL;
	}

	info->request_code = request_code;
	info->cb_func = cbfunc;
	info->err_cb = err_cb;
	info->data = data;

	return info;
}

static void __remove_rescb(aul_svc_cb_info_t *info)
{
	if (info)
		free(info);
}

static int __set_bundle(bundle *b, const char *key, const char *value)
{
	const char *val = NULL;

	val = bundle_get_val(b, key);
	if (val) {
		if (bundle_del(b, key) != 0)
			return AUL_SVC_RET_ERROR;
	}

	if (!value)
		return AUL_SVC_RET_EINVAL;

	if (bundle_add(b, key, value) != 0)
		return AUL_SVC_RET_ERROR;

	_D("__set_bundle");

	return AUL_SVC_RET_OK;
}

static int __set_bundle_array(bundle *b, const char *key,
				const char **value, int len)
{

	int type;
	type = aul_svc_data_is_array(b, key);

	if (type == 1) {
		if (bundle_del(b, key) != 0)
			return AUL_SVC_RET_ERROR;
	}

	if (!value)
		return AUL_SVC_RET_EINVAL;

	if (bundle_add_str_array(b, key, value, len) != 0)
		return AUL_SVC_RET_ERROR;

	_D("__set_bundle_array");

	return AUL_SVC_RET_OK;
}

static void __aul_cb(bundle *b, int is_cancel, void *data)
{
	const char *val = NULL;
	aul_svc_cb_info_t*  cb_info;
	int res;

	if (is_cancel)
		res = AUL_SVC_RES_CANCEL;
	else {
		/* get result_code from bundle */
		val = bundle_get_val(b, AUL_SVC_K_RES_VAL);
		res = (val == NULL) ? AUL_SVC_RES_NOT_OK : atoi(val);
	}

	/* remove result_code from bundle */
	bundle_del(b, AUL_SVC_K_RES_VAL);

	/* find corresponding callback */
	cb_info = (aul_svc_cb_info_t*)data;

	if (cb_info->cb_func) {
		cb_info->cb_func(b, cb_info->request_code,
				(aul_svc_result_val)res, cb_info->data);
		cb_info->cb_func = NULL;
	}

	if (cb_info->err_cb)
		return;

	__remove_rescb(cb_info);
}

static int __error_convert(int res)
{
	switch (res) {
	case AUL_R_EILLACC:
		return AUL_SVC_RET_EILLACC;
	case AUL_R_EINVAL:
		return AUL_SVC_RET_EINVAL;
	case AUL_R_ETERMINATING:
		return AUL_SVC_RET_ETERMINATING;
	case AUL_R_EREJECTED:
		return AUL_SVC_RET_EREJECTED;
	case AUL_R_ENOAPP:
		return AUL_SVC_RET_ENOMATCH;
	default:
		return AUL_SVC_RET_ELAUNCH;
	}
}

static void __aul_error_cb(int err, void *data)
{
	aul_svc_cb_info_t *cb_info = (aul_svc_cb_info_t *)data;

	if (!cb_info) {
		_E("Critical error!");
		return;
	}

	if (err < 0)
		err = __error_convert(err);

	if (cb_info->err_cb) {
		cb_info->err_cb(cb_info->request_code, err, cb_info->data);
		cb_info->err_cb = NULL;
	}

	if (cb_info->cb_func)
		return;

	__remove_rescb(cb_info);
}

static int __run_svc_with_pkgname(char *pkgname, bundle *b, int request_code,
		aul_svc_res_fn cbfunc, aul_svc_err_cb err_cb,
		void *data, uid_t uid, bool sync)
{
	aul_svc_cb_info_t *cb_info = NULL;
	int ret = -1;

	if (bundle_get_type(b, AUL_SVC_K_SELECTOR_EXTRA_LIST) != BUNDLE_TYPE_NONE) {
		if (!aul_svc_get_pkgname(b))
			pkgname = APP_SELECTOR;
	}

	if (bundle_get_val(b, AUL_K_FORCE_LAUNCH_APP_SELECTOR))
		pkgname = APP_SELECTOR;

	if (__is_special_app(pkgname) || __is_special_operation(b)) {
		bundle_del(b, AUL_SVC_K_CAN_BE_LEADER);
		bundle_add_str(b, AUL_SVC_K_CAN_BE_LEADER, "true");
		bundle_del(b, AUL_SVC_K_REROUTE);
		bundle_add_str(b, AUL_SVC_K_REROUTE, "true");
		bundle_del(b, AUL_SVC_K_RECYCLE);
		bundle_add_str(b, AUL_SVC_K_RECYCLE, "true");
	}

	if (cbfunc || err_cb) {
		SECURE_LOGD("pkg_name : %s - with result", pkgname);

		cb_info = __create_rescb(request_code, cbfunc, err_cb, data);
		if (sync) {
			ret = aul_launch_app_with_result_for_uid(pkgname, b,
					__aul_cb, cb_info, uid);
		} else {
			if (err_cb) {
				ret = aul_send_launch_request_for_uid(pkgname,
						b, uid, __aul_cb,
						__aul_error_cb,	cb_info);
			} else {
				ret = aul_launch_app_with_result_async_for_uid(
						pkgname, b, __aul_cb,
						cb_info, uid);
			}
		}
	} else {
		SECURE_LOGD("pkg_name : %s - no result", pkgname);

#ifdef _APPFW_FEATURE_MULTI_INSTANCE
		const char* data = bundle_get_val(b, AUL_SVC_K_MULTI_INSTANCE);
		if (data)
			SECURE_LOGD("multi_instance value = %s", data);

		if (data && strncmp(data, "TRUE", strlen("TRUE")) == 0) {
			if (sync) {
				ret = aul_launch_app_for_multi_instance(pkgname,
						b);
			} else {
				ret = aul_launch_app_for_multi_instance_async(
						pkgname, b);
			}
		} else {
			if (sync)
				ret = aul_launch_app(pkgname, b);
			else
				ret = aul_launch_app_async(pkgname, b, uid);
		}
#else
		if (sync)
			ret = aul_launch_app_for_uid(pkgname, b, uid);
		else
			ret = aul_launch_app_async_for_uid(pkgname, b, uid);
#endif
	}

	if (ret < 0) {
		if (cb_info)
			__remove_rescb(cb_info);
		ret = __error_convert(ret);
	}

	return ret;
}

static int __get_resolve_info(bundle *b, aul_svc_resolve_info_t *info)
{
	char *tmp = NULL;
	char *saveptr = NULL;
	char *strtok_buf = NULL;
	int ret = -1;

	info->op = (char *)aul_svc_get_operation(b);
	info->uri = (char *)aul_svc_get_uri(b);

	if ((info->uri) && (strcmp(info->uri, "") == 0)) {
		_E("Uri is empty");
		return AUL_SVC_RET_EINVAL;
	}

	info->origin_mime = info->mime = (char *)aul_svc_get_mime(b);
	info->pkgname = (char *)aul_svc_get_pkgname(b);
	info->category = (char *)aul_svc_get_category(b);
	info->win_id = (char *)bundle_get_val(b, AUL_SVC_K_WIN_ID);

	SECURE_LOGD("getting resolve info for: operation - %s / uri - %s / mime - %s",
			info->op, info->uri, info->mime);

	if (info->uri) {
		if (strncmp(info->uri, "/", 1) == 0) {
			if (!info->mime) {
				info->origin_mime = info->mime = malloc(MAX_MIME_STR_SIZE);
				if (info->mime == NULL) {
					_E("out of memory");
					return AUL_SVC_RET_ERROR;
				}

				ret = aul_get_mime_from_file(info->uri, info->mime, MAX_MIME_STR_SIZE);
				info->mime_set = 1;
			}
			info->uri = NULL;
		} else if (strncmp(info->uri, "file:///", 8) == 0) {
			if (!info->mime) {
				info->origin_mime = info->mime = malloc(MAX_MIME_STR_SIZE);
				if (info->mime == NULL) {
					_E("out of memory");
					return AUL_SVC_RET_ERROR;
				}

				ret = aul_get_mime_from_file(&info->uri[7], info->mime, MAX_MIME_STR_SIZE);
				info->mime_set = 1;
			}
		} else if (strncmp(info->uri, "file:/", 6) == 0) {
			if (!info->mime) {
				info->origin_mime = info->mime = malloc(MAX_MIME_STR_SIZE);
				if (info->mime == NULL) {
					_E("out of memory");
					return AUL_SVC_RET_ERROR;
				}

				ret = aul_get_mime_from_file(&info->uri[5], info->mime, MAX_MIME_STR_SIZE);
				info->mime_set = 1;
			}
		}

		if (info->mime_set == 1 && ret < 0) {
			_E("aul_get_mime_from_file : %d", ret);
			free(info->mime);
			info->origin_mime = info->mime = NULL;
			info->mime_set = 0;
		}
	}

	if (info->uri) {
		GRegex *regex;
		GMatchInfo *match_info;
		GError *error = NULL;

		regex = g_regex_new("^(([^:/?#]+):)?(//([^/?#]*))?", 0, 0, &error);
		if (g_regex_match(regex, info->uri, 0, &match_info) == FALSE) {
			g_regex_unref(regex);
			return AUL_SVC_RET_EINVAL;
		}

		info->scheme = g_match_info_fetch(match_info, 2);
		info->host = g_match_info_fetch(match_info, 4);

		if (info->scheme && info->host) {
			info->uri_r_info = malloc(MAX_SCHEME_STR_SIZE + MAX_HOST_STR_SIZE + 2);
			if (info->uri_r_info == NULL) {
				_E("out of memory");
				g_match_info_free(match_info);
				g_regex_unref(regex);
				return AUL_SVC_RET_ERROR;
			}

			snprintf(info->uri_r_info, MAX_SCHEME_STR_SIZE + MAX_HOST_STR_SIZE + 1,
						"%s://%s", info->scheme, info->host);
		}

		g_match_info_free(match_info);
		g_regex_unref(regex);

	} else {
		info->scheme = strdup("NULL");
	}

	if (!info->mime) {
		info->mime = strdup("NULL");
		return 0;
	}

	info->m_type = calloc(1, MAX_LOCAL_BUFSZ);
	if (info->m_type == NULL) {
		_E("ouf of memory");
		return AUL_SVC_RET_ERROR;
	}

	info->s_type = calloc(1, MAX_LOCAL_BUFSZ);
	if (info->s_type == NULL) {
		_E("out of memory");
		free(info->m_type);
		return AUL_SVC_RET_ERROR;
	}

	tmp = strdup(info->mime);
	if (tmp == NULL) {
		_E("out of memory");
		free(info->s_type);
		free(info->m_type);
		return AUL_SVC_RET_ERROR;
	}

	strtok_buf = strtok_r(tmp, "/", &saveptr);
	if (strtok_buf)
		strncpy(info->m_type, strtok_buf, MAX_LOCAL_BUFSZ - 1);
	strtok_buf = strtok_r(NULL, "/", &saveptr);
	if (strtok_buf)
		strncpy(info->s_type, strtok_buf, MAX_LOCAL_BUFSZ - 1);
	free(tmp);

	if (strncmp(info->m_type, "*", 1) == 0)
		strncpy(info->m_type, "%", MAX_LOCAL_BUFSZ - 1);
	if (strncmp(info->s_type, "*", 1) == 0)
		strncpy(info->s_type, "%", MAX_LOCAL_BUFSZ - 1);

	info->mime = malloc(MAX_MIME_STR_SIZE);
	if (info->mime == NULL) {
		_E("out of memory");
		free(info->s_type);
		free(info->m_type);
		return AUL_SVC_RET_ERROR;
	}

	snprintf(info->mime, MAX_MIME_STR_SIZE - 1,
			"%s/%s", info->m_type, info->s_type);

	return 0;
}

static int __free_resolve_info_data(aul_svc_resolve_info_t *info)
{
	if (info->mime)
		free(info->mime);
	if (info->scheme)
		free(info->scheme);
	if (info->host)
		free(info->host);
	if (info->m_type)
		free(info->m_type);
	if (info->s_type)
		free(info->s_type);
	if (info->uri_r_info)
		free(info->uri_r_info);
	if (info->mime_set)
		free(info->origin_mime);

	return 0;
}

static char* __get_alias_appid(char *appid)
{
	char *alias_id = NULL;
	char *val = NULL;
	char key_string[MAX_PACKAGE_STR_SIZE + 5];
	dictionary *dic;

	dic = iniparser_load("/usr/share/appsvc/alias.ini");

	if (dic == NULL)
		return NULL;

	snprintf(key_string, sizeof(key_string), "Alias:%s", appid);
	pthread_mutex_lock(&iniparser_lock);
	val = iniparser_getstring(dic, key_string, NULL);
	pthread_mutex_unlock(&iniparser_lock);

	SECURE_LOGD("alias_id : %s", val);

	if (val != NULL) {
		alias_id = malloc(MAX_PACKAGE_STR_SIZE);
		if (alias_id == NULL) {
			_E("out of memory");
			iniparser_freedict(dic);
			return NULL;
		}

		strncpy(alias_id, val, MAX_PACKAGE_STR_SIZE - 1);
	}

	iniparser_freedict(dic);

	return alias_id;
}

static char* __make_query(char *query, char *op, char *uri,
			char *mime, char *m_type, char *s_type)
{
	char tmp[MAX_MIME_STR_SIZE] = { 0, };

	query = _svc_db_query_builder_add(query, op, uri, mime, false);
	if ((mime && strncmp(mime, "NULL", 4) != 0) &&
			(s_type && strncmp(s_type, "%", 1) != 0)) {
		snprintf(tmp, MAX_MIME_STR_SIZE - 1, "%s/*", m_type);
		query = _svc_db_query_builder_add(query, op, uri, tmp, false);
	}

	if ((mime && strncmp(mime, "NULL", 4) != 0) &&
			(m_type && strncmp(m_type, "%", 1) != 0)) {
		snprintf(tmp, MAX_MIME_STR_SIZE - 1, "*/*");
		query = _svc_db_query_builder_add(query, op, uri, tmp, false);
	}

	return query;
}

static char* __make_query_with_collation(char *op, char *uri, char *mime, char *m_type, char *s_type)
{
	char tmp[MAX_MIME_STR_SIZE];
	char *query = NULL;

	query = _svc_db_query_builder_add(query, op, uri, mime, true);

	if (mime && (strncmp(mime, "NULL", 4) != 0) &&
			s_type && (strncmp(s_type, "%", 1) != 0)) {
		snprintf(tmp, MAX_MIME_STR_SIZE - 1, "%s/*", m_type);
		query = _svc_db_query_builder_add(query, op, uri, tmp, true);
	}
	if (mime && (strncmp(mime, "NULL", 4) != 0) &&
			m_type && (strncmp(m_type, "%", 1) != 0)) {
		snprintf(tmp, MAX_MIME_STR_SIZE - 1, "*/*");
		query = _svc_db_query_builder_add(query, op, uri, tmp, true);
	}

	query = _svc_db_query_builder_in("ac.app_control collate appsvc_collation ", query);

	return query;
}


static int __app_list_cb(pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char *appid = NULL;
	GSList **app_list = (GSList **)user_data;
	char *str = NULL;
	GSList *iter = NULL;

	pkgmgrinfo_appinfo_get_appid(handle, &str);
	_D("Matching application is %s", str);

	for (iter = tmp_list; iter != NULL; iter = g_slist_next(iter)) {
		if (strncmp(str, (char *)iter->data, MAX_PACKAGE_STR_SIZE - 1) == 0) {
			appid = strdup(str);
			*app_list = g_slist_append(*app_list, (void *)appid);
			_D("%s is added", appid);
		}
	}

	return 0;
}

static int __get_list_with_category(char *category, GSList **pkg_list, uid_t uid)
{
	int ret;
	pkgmgrinfo_appinfo_filter_h handle;
	GSList *app_list = NULL;
	GSList *iter = NULL;
	char *list_item = NULL;

	ret = pkgmgrinfo_appinfo_filter_create(&handle);
	ret = pkgmgrinfo_appinfo_filter_add_string(handle,
				PMINFO_APPINFO_PROP_APP_CATEGORY, category);

	tmp_list = *pkg_list;
	ret = pkgmgrinfo_appinfo_usr_filter_foreach_appinfo(handle,
				__app_list_cb, &app_list, uid);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_filter_destroy(handle);
		return -1;
	}
	pkgmgrinfo_appinfo_filter_destroy(handle);

	for (iter = *pkg_list; iter != NULL; iter = g_slist_next(iter)) {
		list_item = (char *)iter->data;
		g_free(list_item);
	}
	g_slist_free(*pkg_list);

	*pkg_list = app_list;

	return 0;
}

static int __check_mainapp_mode(char *operation)
{
	return 0;
}

static int __get_list_with_submode(char *operation, char *win_id,
				GSList **pkg_list, uid_t uid)
{
	int ret = 0;
	int mainapp_mode = 0;

	mainapp_mode = __check_mainapp_mode(operation);

	SECURE_LOGD("mainapp_mode : %d", mainapp_mode);

	ret = _svc_db_adjust_list_with_submode(mainapp_mode, win_id, pkg_list, uid);

	if (ret < 0) {
		_E("error: %d", ret);
		return -1;
	}

	return 0;
}

static void __free_pkg_list(GSList *list)
{
	char *list_item;
	GSList *iter = NULL;

	if (list == NULL)
		return;

	for (iter = list; iter != NULL; iter = g_slist_next(iter)) {
		list_item = (char *)iter->data;
		g_free(list_item);
	}
	g_slist_free(list);
}

static gchar *__make_checksum(const char *op, const char *uri, const char *mime)
{
	char buf[MAX_CHECKSUM_BUF];
	gchar *checksum;

	snprintf(buf, sizeof(buf), "%s:%s:%s", op, uri, mime);
	checksum = g_compute_checksum_for_string(G_CHECKSUM_MD5, buf, -1);

	return checksum;
}

static char *__get_cache(const char *checksum, uid_t uid)
{
	app_pkt_t *pkt = NULL;
	int fd;
	int ret;
	bundle *b;
	char buf[MAX_PID_STR_BUFSZ];
	char *appid;

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return NULL;
	}

	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_add(b, AUL_K_TARGET_UID, buf);
	bundle_add(b, AUL_K_CHECKSUM, checksum);

	fd = aul_sock_send_bundle(AUL_UTIL_PID, uid, APP_GET_APPID_FROM_CACHE,
			b, AUL_SOCK_ASYNC);
	bundle_free(b);
	if (fd <= 0)
		return NULL;

	ret = aul_sock_recv_reply_pkt(fd, &pkt);
	if (ret < 0)
		return NULL;

	if (pkt->cmd == APP_GET_APPID_FROM_CACHE) {
		if (pkt->data[0] == 0) {
			free(pkt);
			return NULL;
		}
		appid = strdup((const char *)(pkt->data));
		free(pkt);
		return appid;
	}
	free(pkt);

	return NULL;
}

static void __put_cache(const char *checksum, const char *appid, uid_t uid)
{
	int ret;
	bundle *b;
	char buf[MAX_PID_STR_BUFSZ];

	b = bundle_create();
	if (!b) {
		_E("out of memory");
		return;
	}

	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_add(b, AUL_K_TARGET_UID, buf);
	bundle_add(b, AUL_K_CHECKSUM, checksum);
	bundle_add(b, AUL_K_APPID, appid);

	ret = app_send_cmd_for_uid(AUL_UTIL_PID, uid, APP_SET_CACHE, b);

	if (ret < 0)
		_E("Failed to set cache : %d", ret);

	bundle_free(b);
}

static void __put_cache_with_info(const char *checksum, const char *info, uid_t uid)
{
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "@APP_SELECTOR %s", info);
	__put_cache(checksum, buf, uid);
}

static void __invalidate_cache(uid_t uid)
{
	int ret;
	bundle *b;
	char buf[MAX_PID_STR_BUFSZ];

	b = bundle_create();
	if (!b) {
		_E("out of memory");
		return;
	}

	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_add(b, AUL_K_TARGET_UID, buf);
	ret = app_send_cmd_for_uid(AUL_UTIL_PID, uid, APP_INVALIDATE_CACHE, b);

	if (ret < 0)
		_E("Failed to invalidate cache : %d", ret);

	bundle_free(b);
}

API int aul_svc_set_operation(bundle *b, const char *operation)
{
	if (b == NULL) {
		_E("bundle is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_SVC_K_OPERATION, operation);
}

API int aul_svc_set_uri(bundle *b, const char *uri)
{
	if (b == NULL) {
		_E("bundle is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_SVC_K_URI, uri);
}

API int aul_svc_set_mime(bundle *b, const char *mime)
{
	if (b == NULL) {
		_E("bundle is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_SVC_K_MIME, mime);
}

API int aul_svc_add_data(bundle *b, const char *key, const char *val)
{
	if (b == NULL || key == NULL)
		return AUL_SVC_RET_EINVAL;

	/* check key for data */
	/******************/

	return __set_bundle(b, key, val);
}

API int aul_svc_add_data_array(bundle *b, const char *key,
				const char **val_array, int len)
{
	if (b == NULL || key == NULL)
		return AUL_SVC_RET_EINVAL;

	/* check key for data */
	/******************/

	return __set_bundle_array(b, key, val_array, len);
}

API int aul_svc_set_pkgname(bundle *b, const char *pkg_name)
{
	if (b == NULL) {
		_E("bundle is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_SVC_K_PKG_NAME, pkg_name);
}

API int aul_svc_set_appid(bundle *b, const char *appid)
{
	char *alias_id = NULL;
	int ret;

	if (b == NULL || appid == NULL) {
		_E("bundle is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	alias_id = __get_alias_appid((char *)appid);
	if (alias_id == NULL) {
		ret = __set_bundle(b, AUL_SVC_K_PKG_NAME, appid);
	} else {
		ret = __set_bundle(b, AUL_SVC_K_PKG_NAME, alias_id);
		free(alias_id);
		alias_id = NULL;
	}

	return ret;
}

API int aul_svc_set_category(bundle *b, const char *category)
{
	if (b == NULL) {
		_E("bundle is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_SVC_K_CATEGORY, category);
}

API int aul_svc_set_launch_mode(bundle *b, const char *mode)
{
	if (b == NULL) {
		_E("bundle is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_SVC_K_LAUNCH_MODE, mode);
}

static int __run_service(bundle *b, int request_code,
		aul_svc_res_fn cbfunc, aul_svc_err_cb err_cb,
		void *data, uid_t uid, bool sync)
{
	aul_svc_resolve_info_t info;
	char *pkgname;
	char *operation;
	int pkg_count = 0;
	int ret = -1;
	char *appid;
	int l;
	GSList *pkg_list = NULL;
	char *query = NULL;
	gchar *checksum;

	if (b == NULL) {
		_E("bundle is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	pkgname = (char *)aul_svc_get_pkgname(b);
	operation = (char *)aul_svc_get_operation(b);

	/* explict*/
	if (pkgname) {
		if (operation == NULL)
			aul_svc_set_operation(b, AUL_SVC_OPERATION_DEFAULT);
		ret = __run_svc_with_pkgname(pkgname, b, request_code, cbfunc,
				err_cb, data, uid, sync);
		return ret;
	}

	/* share panel */
	if (TIZEN_FEATURE_SHARE_PANEL
		&& (operation && (strcmp(operation, AUL_SVC_OPERATION_SHARE) == 0
		|| strcmp(operation, AUL_SVC_OPERATION_MULTI_SHARE) == 0
		|| strcmp(operation, AUL_SVC_OPERATION_SHARE_TEXT) == 0))) {
		ret = __run_svc_with_pkgname(SHARE_PANEL, b, request_code,
				cbfunc, err_cb, data, uid, sync);
		return ret;
	}

	memset(&info, 0, sizeof(aul_svc_resolve_info_t));
	ret = __get_resolve_info(b, &info);
	if (ret < 0) {
		__free_resolve_info_data(&info);
		return ret;
	}

	SECURE_LOGD("op - %s / mime - %s / scheme - %s",
					info.op, info.origin_mime, info.scheme);

	checksum = __make_checksum(info.op, info.uri, info.origin_mime);
	appid = __get_cache(checksum, uid);

	if (appid) {
		_D("Hit! %s / %s", checksum, appid);
		l = strlen("@APP_SELECTOR ");
		if (!strncmp("@APP_SELECTOR ", appid, l)) {
			bundle_add(b, AUL_SVC_K_URI_R_INFO, &appid[l]);
			ret = __run_svc_with_pkgname(APP_SELECTOR, b,
					request_code, cbfunc, err_cb,
					data, uid, sync);
		} else if (!strcmp(appid, "^")) {
			ret = AUL_SVC_RET_ENOMATCH;
		} else {
			ret = __run_svc_with_pkgname(appid, b, request_code,
				cbfunc, err_cb, data, uid, sync);
		}
		free(appid);
		g_free(checksum);
		__free_resolve_info_data(&info);
		return ret;
	}

	ret = _svc_db_check_perm(uid, true);
	if (ret < 0) {
		_E("permission error : %d", ret);
		ret = AUL_SVC_RET_EILLACC;
		goto end;
	}

	/*uri*/
	pkgname = _svc_db_get_app(info.op, info.origin_mime, info.uri, uid);
	if (pkgname != NULL) {
		__put_cache(checksum, pkgname, uid);
		ret = __run_svc_with_pkgname(pkgname, b, request_code,
			cbfunc, err_cb, data, uid, sync);
		free(pkgname);
		goto end;
	}

	query = __make_query_with_collation(info.op, info.uri,
			info.mime, info.m_type, info.s_type);

	query = _svc_db_query_builder_build(query);
	_svc_db_exec_query(query, &pkg_list, uid);
	if (query) {
		free(query);
		query = NULL;
	}

	pkg_count = g_slist_length(pkg_list);
	if (pkg_count > 0) {
		__free_pkg_list(pkg_list);
		pkg_list = NULL;
		if (info.uri_r_info) {
			query = __make_query(query, info.op, info.uri_r_info,
				info.mime, info.m_type, info.s_type);
		}

		query = __make_query(query, info.op, info.scheme,
			info.mime, info.m_type, info.s_type);

		query = __make_query(query, info.op, "*",
			info.mime, info.m_type, info.s_type);

		if (info.scheme && (strcmp(info.scheme, "file") == 0)
			&& info.mime && (strcmp(info.mime, "NULL") != 0)) {
			query = __make_query(query, info.op, "NULL",
				info.mime, info.m_type, info.s_type);
		}

		query = _svc_db_query_builder_build(query);
		_svc_db_exec_query(query, &pkg_list, uid);
		if (query) {
			free(query);
			query = NULL;
		}

		if (info.category)
			__get_list_with_category(info.category, &pkg_list, uid);

		__get_list_with_submode(info.op, info.win_id, &pkg_list, uid);

		pkg_count = g_slist_length(pkg_list);
		_D("pkg_count : %d", pkg_count);

		if (pkg_count == 1) {
			pkgname = (char *)pkg_list->data;
			if (pkgname != NULL) {
				__put_cache(checksum, pkgname, uid);
				ret = __run_svc_with_pkgname(pkgname, b, request_code,
						cbfunc, err_cb, data, uid, sync);
				goto end;
			}
		} else if (pkg_count > 1) {
			bundle_add(b, AUL_SVC_K_URI_R_INFO, info.uri);
			__put_cache_with_info(checksum, info.uri, uid);
			ret = __run_svc_with_pkgname(APP_SELECTOR, b, request_code,
					cbfunc, err_cb, data, uid, sync);
			goto end;
		}
		__free_pkg_list(pkg_list);
		pkg_list = NULL;
	}

	/*scheme & host*/
	if (info.uri_r_info) {
		pkgname = _svc_db_get_app(info.op, info.origin_mime, info.uri_r_info, uid);

		if (pkgname != NULL) {
			__put_cache(checksum, pkgname, uid);
			ret = __run_svc_with_pkgname(pkgname, b, request_code,
					cbfunc, err_cb, data, uid, sync);
			free(pkgname);
			goto end;
		}

		query = __make_query(query, info.op, info.uri_r_info,
			info.mime, info.m_type, info.s_type);
		query = _svc_db_query_builder_build(query);
		_svc_db_exec_query(query, &pkg_list, uid);
		if (query) {
			free(query);
			query = NULL;
		}

		pkg_count = g_slist_length(pkg_list);
		if (pkg_count > 0) {
			__free_pkg_list(pkg_list);
			pkg_list = NULL;
			query = __make_query(query, info.op, "*",
			info.mime, info.m_type, info.s_type);

			if (info.scheme && (strcmp(info.scheme, "file") == 0)
				&& info.mime && (strcmp(info.mime, "NULL") != 0)) {
				query = __make_query(query, info.op, "NULL",
					info.mime, info.m_type, info.s_type);
			}

			query = _svc_db_query_builder_build(query);
			_svc_db_exec_query(query, &pkg_list, uid);
			if (query) {
				free(query);
				query = NULL;
			}

			if (info.category)
				__get_list_with_category(info.category, &pkg_list, uid);

			__get_list_with_submode(info.op, info.win_id, &pkg_list, uid);

			pkg_count = g_slist_length(pkg_list);
			_D("pkg_count : %d", pkg_count);

			if (pkg_count == 1) {
				pkgname = (char *)pkg_list->data;
				if (pkgname != NULL) {
					__put_cache(checksum, pkgname, uid);
					ret = __run_svc_with_pkgname(pkgname, b, request_code,
							cbfunc, err_cb, data, uid, sync);
					goto end;
				}
			} else if (pkg_count > 1) {
				bundle_add(b, AUL_SVC_K_URI_R_INFO, info.uri_r_info);
				__put_cache_with_info(checksum, info.uri_r_info, uid);
				ret = __run_svc_with_pkgname(APP_SELECTOR, b, request_code,
					cbfunc, err_cb, data, uid, sync);
				goto end;
			}

			__free_pkg_list(pkg_list);
			pkg_list = NULL;
		}
	}

	/*scheme*/
	pkgname = _svc_db_get_app(info.op, info.origin_mime, info.scheme, uid);

	if (pkgname != NULL) {
		__put_cache(checksum, pkgname, uid);
		ret = __run_svc_with_pkgname(pkgname, b, request_code,
			cbfunc, err_cb, data, uid, sync);
		free(pkgname);
		goto end;
	}

	query = __make_query(query, info.op, info.scheme,
		info.mime, info.m_type, info.s_type);

	query = __make_query(query, info.op, "*",
		info.mime, info.m_type, info.s_type);

	if (info.scheme && (strcmp(info.scheme, "file") == 0)
			&& info.mime && (strcmp(info.mime, "NULL") != 0)) {
		query = __make_query(query, info.op, "NULL",
			info.mime, info.m_type, info.s_type);
	}

	query = _svc_db_query_builder_build(query);
	_svc_db_exec_query(query, &pkg_list, uid);

	if (query) {
		free(query);
		query = NULL;
	}

	if (info.category)
		__get_list_with_category(info.category, &pkg_list, uid);

	__get_list_with_submode(info.op, info.win_id, &pkg_list, uid);

	pkg_count = g_slist_length(pkg_list);
	_D("pkg_count : %d", pkg_count);

	if (pkg_count == 1) {
		pkgname = (char *)pkg_list->data;
		if (pkgname != NULL) {
			__put_cache(checksum, pkgname, uid);
			ret = __run_svc_with_pkgname(pkgname, b, request_code,
					cbfunc, err_cb, data, uid, sync);
		}
	} else if (pkg_count < 1) {
		__free_resolve_info_data(&info);
		__put_cache(checksum, "^", uid);
		g_free(checksum);
		return AUL_SVC_RET_ENOMATCH;
	} else {
		bundle_add(b, AUL_SVC_K_URI_R_INFO, info.scheme);
		__put_cache_with_info(checksum, info.scheme, uid);
		ret = __run_svc_with_pkgname(APP_SELECTOR, b, request_code,
				cbfunc, err_cb, data, uid, sync);
	}

end:
	__free_pkg_list(pkg_list);
	__free_resolve_info_data(&info);
	g_free(checksum);

	return ret;
}

API int aul_svc_run_service(bundle *b, int request_code,
		aul_svc_res_fn cbfunc, void *data)
{
	return __run_service(b, request_code, cbfunc, NULL, data,
			getuid(), true);
}

API int aul_svc_run_service_for_uid(bundle *b, int request_code,
		aul_svc_res_fn cbfunc, void *data, uid_t uid)
{
	return __run_service(b, request_code, cbfunc, NULL, data, uid, true);
}

API int aul_svc_get_list(bundle *b, aul_svc_info_iter_fn iter_fn,
		void *data)
{
	return aul_svc_get_list_for_uid(b, iter_fn, data, getuid());
}

API int aul_svc_get_list_for_uid(bundle *b, aul_svc_info_iter_fn iter_fn,
		void *data, uid_t uid)
{
	aul_svc_resolve_info_t info;
	char *pkgname = NULL;
	int pkg_count;
	int ret = -1;

	GSList *pkg_list = NULL;
	GSList *iter = NULL;
	char *query = NULL;
	char *query2 = NULL;

	if (b == NULL) {
		_E("bundle is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	if (iter_fn == NULL) {
		_E("iter_fn is NULL");
		return AUL_SVC_RET_EINVAL;
	}


	/* parse bundle */
	memset(&info, 0, sizeof(aul_svc_resolve_info_t));
	ret = __get_resolve_info(b, &info);
	if (ret < 0) {
		__free_resolve_info_data(&info);
		return ret;
	}

	_D("operation - %s / shceme - %s / mime - %s", info.op, info.scheme,
	   info.mime);

	query2 = __make_query_with_collation(info.op, info.uri,
			info.mime, info.m_type, info.s_type);

	if (info.uri_r_info) {
		query = __make_query(query, info.op, info.uri_r_info,
			info.mime, info.m_type, info.s_type);
	}

	query = __make_query(query, info.op, info.scheme,
		info.mime, info.m_type, info.s_type);

	query = __make_query(query, info.op, "*",
		info.mime, info.m_type, info.s_type);

	if (info.scheme && (strcmp(info.scheme, "file") == 0)
		&& info.mime && (strcmp(info.mime, "NULL") != 0)) {
		query = __make_query(query, info.op, "NULL",
			info.mime, info.m_type, info.s_type);
	}

	query = _svc_db_query_builder_or(query2, query);
	query = _svc_db_query_builder_build(query);
	_svc_db_exec_query(query, &pkg_list, uid);
	if (query) {
		free(query);
		query = NULL;
	}

	if (info.category)
		__get_list_with_category(info.category, &pkg_list, uid);

	__get_list_with_submode(info.op, info.win_id, &pkg_list, uid);

	pkg_count = g_slist_length(pkg_list);
	if (pkg_count == 0) {
		_E("Cannot find associated application");

		__free_resolve_info_data(&info);
		return AUL_SVC_RET_ENOMATCH;
	}

	for (iter = pkg_list; iter != NULL; iter = g_slist_next(iter)) {
		pkgname = iter->data;
		SECURE_LOGD("PKGNAME : %s", pkgname);
		if (iter_fn(pkgname, data) != 0)
			break;
		g_free(pkgname);
	}

	g_slist_free(pkg_list);
	__free_resolve_info_data(&info);

	return AUL_SVC_RET_OK;
}

API int aul_svc_get_all_defapps(aul_svc_info_iter_fn iter_fn, void *data)
{
	return aul_svc_get_all_defapps_for_uid(iter_fn, data, getuid());
}

API int aul_svc_get_all_defapps_for_uid(aul_svc_info_iter_fn iter_fn,
		void *data, uid_t uid)
{
	char *pkgname = NULL;
	int ret = -1;

	GSList *pkg_list = NULL;
	GSList *iter = NULL;


	ret = _svc_db_check_perm(uid, true);
	if (ret < 0) {
		_E("permission error : %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_get_list_with_all_defapps(&pkg_list, uid);
	if (ret < 0)
		return ret;

	for (iter = pkg_list; iter != NULL; iter = g_slist_next(iter)) {
		pkgname = iter->data;
		if (iter_fn(pkgname, data) != 0)
			break;
		g_free(pkgname);
	}

	g_slist_free(pkg_list);

	return AUL_SVC_RET_OK;
}

API const char *aul_svc_get_operation(bundle *b)
{
	return bundle_get_val(b, AUL_SVC_K_OPERATION);
}

API const char *aul_svc_get_uri(bundle *b)
{
	return bundle_get_val(b, AUL_SVC_K_URI);
}

API const char *aul_svc_get_mime(bundle *b)
{
	return bundle_get_val(b, AUL_SVC_K_MIME);
}

API const char *aul_svc_get_data(bundle *b, const char *key)
{
	return bundle_get_val(b, key);
}

API const char **aul_svc_get_data_array(bundle *b, const char *key, int *len)
{
	return bundle_get_str_array(b, key, len);
}

API const char *aul_svc_get_pkgname(bundle *b)
{
	return bundle_get_val(b, AUL_SVC_K_PKG_NAME);
}

API const char *aul_svc_get_appid(bundle *b)
{
	return bundle_get_val(b, AUL_SVC_K_PKG_NAME);
}

API const char *aul_svc_get_category(bundle *b)
{
	return bundle_get_val(b, AUL_SVC_K_CATEGORY);
}

API const char *aul_svc_get_launch_mode(bundle *b)
{
	return bundle_get_val(b, AUL_SVC_K_LAUNCH_MODE);
}

API int aul_svc_create_result_bundle(bundle *inb, bundle **outb)
{
	int ret = -1;

	if (inb == NULL || outb == NULL) {
		_E("bundle is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	ret = aul_create_result_bundle(inb, outb);

	/* add additional bundle */
	/*  bundle_add(outb, " ", " ");  */

	if (ret == AUL_R_OK)
		ret = AUL_SVC_RET_OK;
	else if (ret == AUL_R_EINVAL)
		ret = AUL_SVC_RET_EINVAL;
	else if (ret == AUL_R_ECANCELED)
		ret = AUL_SVC_RET_ECANCELED;
	else
		ret = AUL_SVC_RET_ERROR;

	return ret;
}

API int aul_svc_send_result(bundle *b, aul_svc_result_val result)
{
	int ret;
	char tmp[MAX_LOCAL_BUFSZ];

	if (b == NULL) {
		_E("aul_svc_send_result is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	/* add result_code to bundle */
	snprintf(tmp, MAX_LOCAL_BUFSZ, "%d", (int)result);
	ret = __set_bundle(b, AUL_SVC_K_RES_VAL, tmp);
	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	if (result == AUL_SVC_RES_CANCEL)
		ret = aul_send_result(b, 1);
	else
		ret = aul_send_result(b, 0);

	/* remove result_code from bundle */
	bundle_del(b, AUL_SVC_K_RES_VAL);

	return ret;
}

API int aul_svc_set_defapp(const char *op, const char *mime_type,
				const char *uri, const char *defapp)
{
	return aul_svc_set_defapp_for_uid(op, mime_type, uri, defapp, getuid());
}

API int aul_svc_set_defapp_for_uid(const char *op, const char *mime_type,
				const char *uri, const char *defapp, uid_t uid)
{
	int ret;

	if (op == NULL || defapp == NULL)
		return AUL_SVC_RET_EINVAL;

	ret = _svc_db_check_perm(uid, false);
	if (ret < 0) {
		_E("permission error : %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_add_app(op, mime_type, uri, defapp, uid);
	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	return AUL_SVC_RET_OK;
}

API int aul_svc_unset_defapp(const char *defapp)
{
	return aul_svc_unset_defapp_for_uid(defapp, getuid());
}

API int aul_svc_unset_defapp_for_uid(const char *defapp, uid_t uid)
{
	int ret;

	if (defapp == NULL)
		return AUL_SVC_RET_EINVAL;

	ret = _svc_db_check_perm(uid, false);
	if (ret < 0) {
		_E("permission error : %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_delete_with_pkgname(defapp, uid);

	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	return AUL_SVC_RET_OK;
}

API int aul_svc_unset_all_defapps()
{
	return aul_svc_unset_all_defapps_for_uid(getuid());
}

API int aul_svc_unset_all_defapps_for_uid(uid_t uid)
{
	int ret;

	ret = _svc_db_check_perm(uid, false);
	if (ret < 0) {
		_E("permission error : %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_delete_all(uid);

	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	__invalidate_cache(uid);
	return AUL_SVC_RET_OK;
}

API int aul_svc_is_defapp(const char *pkg_name)
{
	return aul_svc_is_defapp_for_uid(pkg_name, getuid());
}

API int aul_svc_is_defapp_for_uid(const char *pkg_name, uid_t uid)
{
	int ret;

	ret = _svc_db_check_perm(uid, true);
	if (ret < 0) {
		_E("permission error : %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	return _svc_db_is_defapp(pkg_name, uid);
}

API int aul_svc_data_is_array(bundle *b, const char *key)
{
	int type;
	type = bundle_get_type(b, key);

	if (type <= 0)
		return 0;

	if (type & BUNDLE_TYPE_ARRAY)
		return 1;
	return 0;
}

API int aul_svc_allow_transient_app(bundle *b, int wid)
{
	char win_id[MAX_LOCAL_BUFSZ];

	snprintf(win_id, MAX_LOCAL_BUFSZ, "%d", wid);

	if (b == NULL) {
		_E("bundle is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_SVC_K_WIN_ID, win_id);
}

API int aul_svc_request_transient_app(bundle *b, int callee_wid,
				aul_svc_host_res_fn cbfunc, void *data)
{
	return 0;
}

API int aul_svc_subapp_terminate_request_pid(int pid)
{
	int cpid = getpid();
	int lcnt;
	int *lpids = NULL;
	int i;

	aul_app_group_get_leader_pids(&lcnt, &lpids);
	for (i = 0; i < lcnt; i++) {
		if (lpids[i] == cpid) {
			int cnt;
			int *pids = NULL;

			aul_app_group_get_group_pids(cpid, &cnt, &pids);

			if (cnt == 0) {
				free(lpids);
				if (pids)
					free(pids);

				return aul_subapp_terminate_request_pid(pid);
			}

			if (pids != NULL)
				free(pids);
			break;
		}
	}

	if (lpids != NULL)
		free(lpids);

	return aul_app_group_clear_top();
}

API int aul_send_service_result(bundle *b)
{
	return aul_send_result(b, 0);
}

API int aul_svc_subscribe_launch_result(bundle *b, const char *result)
{
	if (b == NULL) {
		_E("bundle is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, result, "1");
}

API int aul_svc_set_loader_id(bundle *b, int loader_id)
{
	char tmp[MAX_LOCAL_BUFSZ];

	if (b == NULL) {
		_E("bundle is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	if (loader_id <= 0) {
		_E("invalid loader id");
		return AUL_SVC_RET_EINVAL;
	}

	snprintf(tmp, sizeof(tmp), "%d", loader_id);
	return __set_bundle(b, AUL_K_LOADER_ID, tmp);
}

API int aul_svc_set_loader_name(bundle *b, const char *loader_name)
{
	if (b == NULL) {
		_E("bundle is NULL");
		return AUL_SVC_RET_EINVAL;
	}

	if (!loader_name) {
		_E("invalid loader name");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_K_LOADER_NAME, loader_name);
}

API int aul_svc_set_background_launch(bundle *b, int enabled)
{
	if (b == NULL)
		return AUL_R_EINVAL;

	if (bundle_get_type(b, AUL_SVC_K_BG_LAUNCH) != BUNDLE_TYPE_NONE)
		bundle_del(b, AUL_SVC_K_BG_LAUNCH);

	if (enabled)
		bundle_add_str(b, AUL_SVC_K_BG_LAUNCH, "enable");

	return AUL_R_OK;
}

API int aul_svc_set_alias_appid(const char *alias_appid, const char *appid)
{
	return aul_svc_set_alias_appid_for_uid(alias_appid, appid, getuid());
}

API int aul_svc_set_alias_appid_for_uid(const char *alias_appid,
		const char *appid, uid_t uid)
{
	int ret;

	ret = _svc_db_check_perm(uid, false);
	if (ret < 0) {
		_E("Permission error: %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_add_alias_appid(alias_appid, appid, uid);
	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	return AUL_SVC_RET_OK;
}

API int aul_svc_unset_alias_appid(const char *alias_appid)
{
	return aul_svc_unset_alias_appid_for_uid(alias_appid, getuid());
}

API int aul_svc_unset_alias_appid_for_uid(const char *alias_appid, uid_t uid)
{
	int ret;

	ret = _svc_db_check_perm(uid, false);
	if (ret < 0) {
		_E("Permission error: %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_delete_alias_appid(alias_appid, uid);
	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	return AUL_SVC_RET_OK;
}

API int aul_svc_foreach_alias_info(void (*callback)(const char *alias_appid,
			const char *appid, void *data), void *user_data)
{
	return aul_svc_foreach_alias_info_for_uid(callback, getuid(),
			user_data);
}

API int aul_svc_foreach_alias_info_for_uid(void (*callback)(
			const char *alias_appid, const char *appid,
			void *data), uid_t uid, void *user_data)
{
	int ret;

	if (callback == NULL) {
		_E("Invalid parameter");
		return AUL_SVC_RET_EINVAL;
	}

	ret = _svc_db_check_perm(uid, true);
	if (ret < 0) {
		_E("Permission error: %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_foreach_alias_info(callback, uid, user_data);
	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	return AUL_SVC_RET_OK;
}

API int aul_svc_enable_alias_info(const char *appid)
{
	return aul_svc_enable_alias_info_for_uid(appid, getuid());
}

API int aul_svc_enable_alias_info_for_uid(const char *appid, uid_t uid)
{
	int ret;

	ret = _svc_db_check_perm(uid, false);
	if (ret < 0) {
		_E("Permission error: %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_enable_alias_info(appid, uid);
	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	return AUL_SVC_RET_OK;
}

API int aul_svc_disable_alias_info(const char *appid)
{
	return aul_svc_disable_alias_info_for_uid(appid, getuid());
}

API int aul_svc_disable_alias_info_for_uid(const char *appid, uid_t uid)
{
	int ret;

	ret = _svc_db_check_perm(uid, false);
	if (ret < 0) {
		_E("Permission error: %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_disable_alias_info(appid, uid);
	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	return AUL_SVC_RET_OK;
}

API int aul_svc_get_appid_by_alias_appid(const char *alias_appid, char **appid)
{
	return aul_svc_get_appid_by_alias_appid_for_uid(alias_appid,
			appid, getuid());
}

API int aul_svc_get_appid_by_alias_appid_for_uid(const char *alias_appid,
		char **appid, uid_t uid)
{
	int ret;

	ret = _svc_db_check_perm(uid, true);
	if (ret < 0) {
		_E("Permission error: %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_get_appid_from_alias_info(alias_appid, appid, uid);
	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	return AUL_SVC_RET_OK;
}

API int aul_svc_foreach_alias_info_by_appid(int (*callback)(
			const char *alias_appid, const char *appid, void *data),
		const char *appid, void *user_data)
{
	return aul_svc_foreach_alias_info_by_appid_for_uid(callback, appid,
			getuid(), user_data);
}

API int aul_svc_foreach_alias_info_by_appid_for_uid(int (*callback)(
			const char *alias_appid, const char *appid, void *data),
		const char *appid, uid_t uid, void *user_data)
{
	int ret;

	if (callback == NULL || appid == NULL) {
		_E("Invalid parameter");
		return AUL_SVC_RET_EINVAL;
	}

	ret = _svc_db_check_perm(uid, true);
	if (ret < 0) {
		_E("Permission error: %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_foreach_alias_info_by_appid(callback, appid,
			uid, user_data);
	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	return AUL_SVC_RET_OK;
}

API int aul_svc_foreach_allowed_info(int (*callback)(const char *appid,
			const char *allowed_appid, void *data), void *user_data)
{
	return aul_svc_foreach_allowed_info_for_uid(callback,
			getuid(), user_data);
}

API int aul_svc_foreach_allowed_info_for_uid(int (*callback)(const char *appid,
			const char *allowed_appid, void *data),
		uid_t uid, void *user_data)
{
	int ret;

	if (callback == NULL) {
		_E("Invalid parameter");
		return AUL_SVC_RET_EINVAL;
	}

	ret = _svc_db_check_perm(uid, true);
	if (ret < 0) {
		_E("Permission error: %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_foreach_allowed_info(callback, uid, user_data);
	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	return AUL_SVC_RET_OK;
}

API int aul_svc_foreach_allowed_info_by_appid(int (*callback)(
			const char *appid, const char *allowed_appid, void *data),
		const char *appid, void *user_data)
{
	return aul_svc_foreach_allowed_info_by_appid_for_uid(callback,
			appid, getuid(), user_data);
}

API int aul_svc_foreach_allowed_info_by_appid_for_uid(int (*callback)(
			const char *appid, const char *allowed_appid, void *data),
		const char *appid, uid_t uid, void *user_data)
{
	int ret;

	if (callback == NULL || appid == NULL) {
		_E("Invalid parameter");
		return AUL_SVC_RET_EINVAL;
	}

	ret = _svc_db_check_perm(uid, true);
	if (ret < 0) {
		_E("Permission error: %d", ret);
		return AUL_SVC_RET_EILLACC;
	}

	ret = _svc_db_foreach_allowed_info_by_appid(callback, appid,
			uid, user_data);
	if (ret < 0)
		return AUL_SVC_RET_ERROR;

	return AUL_SVC_RET_OK;
}

API const char *aul_svc_get_instance_id(bundle *b)
{
	return bundle_get_val(b, AUL_K_INSTANCE_ID);
}

API int aul_svc_set_instance_id(bundle *b, const char *instance_id)
{
	if (b == NULL || instance_id == NULL) {
		_E("Invalid parameter");
		return AUL_SVC_RET_EINVAL;
	}

	return __set_bundle(b, AUL_K_INSTANCE_ID, instance_id);
}

API int aul_svc_run_service_async(bundle *b, int request_code,
		aul_svc_res_fn cbfunc, void *data)
{
	return __run_service(b, request_code, cbfunc, NULL, data,
			getuid(), false);
}

API int aul_svc_run_service_async_for_uid(bundle *b, int request_code,
		aul_svc_res_fn cbfunc, void *data, uid_t uid)
{
	return __run_service(b, request_code, cbfunc, NULL, data, uid, false);
}

API int aul_svc_send_launch_request(bundle *b, int request_code,
		aul_svc_res_fn cbfunc, aul_svc_err_cb err_cb,
		void *user_data)
{
	return aul_svc_send_launch_request_for_uid(b, request_code,
			cbfunc, err_cb, user_data, getuid());
}

API int aul_svc_send_launch_request_for_uid(bundle *b, int request_code,
		aul_svc_res_fn cbfunc, aul_svc_err_cb err_cb,
		void *user_data, uid_t uid)
{
	return __run_service(b, request_code, cbfunc, err_cb, user_data,
			uid, false);
}
