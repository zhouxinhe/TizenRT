/*
 * Copyright (c) 2014 - 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <linux/limits.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <tzplatform_config.h>
#include <pkgmgr-info.h>
#include <storage-internal.h>

#include "aul_api.h"
#include "aul_util.h"
#include "aul.h"

#define ROOT_UID 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define DEFAULT_EXTERNAL_STORAGE "/opt/media/sdcard"

static const char _DATA_DIR[] = "data/";
static const char _CACHE_DIR[] = "cache/";
static const char _RESOURCE_DIR[] = "res/";
static const char _TEP_RESOURCE_DIR[] = "tep/mount/";
static const char _SHARED_DATA_DIR[] = "shared/data/";
static const char _SHARED_TRUSTED_DIR[] = "shared/trusted/";
static const char _SHARED_RESOURCE_DIR[] = "shared/res/";

static const char * __get_specific_path(const char *pkgid, uid_t uid)
{
	const char * path;
	char buf[PATH_MAX];

	if (uid == ROOT_UID || uid == GLOBAL_USER) {
		path = tzplatform_getenv(TZ_SYS_RO_APP);
		snprintf(buf, sizeof(buf), "%s/%s", path, pkgid);
		if (access(buf, R_OK) != 0)
			path = tzplatform_getenv(TZ_SYS_RW_APP);
	} else {
		tzplatform_set_user(uid);
		path = tzplatform_getenv(TZ_USER_APP);
		tzplatform_reset_user();
	}
	return path;
}

static int __get_pkgid(char *pkgid, int len, const char *appid, uid_t uid)
{
	pkgmgrinfo_appinfo_h appinfo;
	char *_pkgid;
	int ret;

	if (appid == NULL)
		return aul_app_get_pkgid_bypid(getpid(), pkgid, len);

	ret = pkgmgrinfo_appinfo_get_usr_appinfo(appid, uid, &appinfo);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get app info. (ret:%d)", ret);
		return AUL_R_ENOAPP;
	}

	ret = pkgmgrinfo_appinfo_get_pkgid(appinfo, &_pkgid);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get pkgid. (ret:%d)", ret);
		pkgmgrinfo_appinfo_destroy_appinfo(appinfo);
		return AUL_R_ENOAPP;
	}

	snprintf(pkgid, len, "%s", _pkgid);
	pkgmgrinfo_appinfo_destroy_appinfo(appinfo);

	return AUL_R_OK;
}

/* return value should be freed after use. */
static char *__get_sdcard_path(void)
{
	char *sdpath = NULL;
	char *result_path = NULL;
	int storage_id = 0;
	int ret;

	ret = storage_get_primary_sdcard(&storage_id, &sdpath);
	if (ret != STORAGE_ERROR_NONE)
		_W("failed to get primary sdcard (%d)", ret);

	if (sdpath)
		result_path = sdpath;
	else
		result_path = strdup(DEFAULT_EXTERNAL_STORAGE);

	return result_path;
}

static int __get_external_path(char **path, const char *appid,
		const char *dir_name, uid_t uid)
{
	char buf[PATH_MAX];
	char pkgid[NAME_MAX];
	char *ext_path;
	int ret;

	ret = __get_pkgid(pkgid, sizeof(pkgid), appid, uid);
	if (ret != AUL_R_OK)
		return ret;

	assert(path);

	*path = NULL;
	ext_path = __get_sdcard_path();
	if (ext_path) {
		tzplatform_set_user(uid);
		snprintf(buf, sizeof(buf), "%s/apps/%s/apps_rw/%s/%s",
			ext_path, tzplatform_getenv(TZ_USER_NAME),
			pkgid, dir_name ? dir_name : "");
		tzplatform_reset_user();
		free(ext_path);
		ext_path = NULL;

		*path = strdup(buf);
	}
	ret = AUL_R_OK;

	return ret;
}

static int __get_path(char **path, const char *appid, const char *dir_name,
		uid_t uid)
{
	char buf[PATH_MAX];
	char pkgid[NAME_MAX];
	int ret;

	ret = __get_pkgid(pkgid, sizeof(pkgid), appid, uid);
	if (ret != AUL_R_OK)
		return ret;

	snprintf(buf, sizeof(buf), "%s/%s/%s", __get_specific_path(pkgid, uid),
			pkgid, dir_name ? dir_name : "");
	*path = strdup(buf);

	return AUL_R_OK;
}

static int __get_path_from_db(char **path, const char *appid, const char *dir_name,
		uid_t uid)
{
	char *_path;
	char buf[PATH_MAX];
	char appid_buf[NAME_MAX];
	int ret;
	pkgmgrinfo_appinfo_h appinfo;
	int len;
	const char *root_path;

	root_path = aul_get_preinit_root_path();
	if (appid == NULL && root_path) {
		len = strlen(root_path);
		snprintf(buf, sizeof(buf), "%s%s%s", root_path,
			root_path[len - 1] == '/' ?  "" : "/",
			dir_name ? dir_name : "");
		*path = strdup(buf);
		return AUL_R_OK;
	}

	if (appid == NULL) {
		ret = aul_app_get_appid_bypid(getpid(), appid_buf,
				sizeof(appid_buf));
		if (ret != AUL_R_OK) {
			_E("appid is not given and failed to get appid");
			return ret;
		}
	}

	ret = pkgmgrinfo_appinfo_get_usr_appinfo(appid ? appid : appid_buf, uid,
			&appinfo);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get appinfo. (ret:%d)", ret);
		return AUL_R_ENOAPP;
	}
	ret = pkgmgrinfo_appinfo_get_root_path(appinfo, &_path);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get root path. (ret:%d)", ret);
		pkgmgrinfo_appinfo_destroy_appinfo(appinfo);
		return AUL_R_ERROR;
	}

	len = _path ? strlen(_path) : 0;
	if (len == 0) {
		_E("Root path is null or empty");
		pkgmgrinfo_appinfo_destroy_appinfo(appinfo);
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%s%s%s", _path,
			_path[len - 1] == '/' ?  "" : "/",
			dir_name ? dir_name : "");

	pkgmgrinfo_appinfo_destroy_appinfo(appinfo);

	assert(path);
	*path = strdup(buf);

	return AUL_R_OK;
}

static const char *__get(char **path, const char *appid,
		const char *dir_name, uid_t uid,
		int (*func_get)(char **, const char *, const char *, uid_t))
{
	int r;

	if (*path)
		return *path;

	assert(func_get);

	r = func_get(path, appid, dir_name, uid);
	if (r != AUL_R_OK)
		return NULL;

	return *path;
}

API const char *aul_get_app_external_root_path(void)
{
	static char *path;

	return __get(&path, NULL, NULL, getuid(), __get_external_path);
}

API const char *aul_get_app_root_path(void)
{
	static char *path;

	return __get(&path, NULL, NULL, getuid(), __get_path_from_db);
}

API const char *aul_get_app_data_path(void)
{
	static char *path;

	return __get(&path, NULL, _DATA_DIR, getuid(), __get_path);
}

API const char *aul_get_app_cache_path(void)
{
	static char *path;

	return __get(&path, NULL, _CACHE_DIR, getuid(), __get_path);
}

API const char *aul_get_app_resource_path(void)
{
	static char *path;

	return __get(&path, NULL, _RESOURCE_DIR, getuid(), __get_path_from_db);
}

API const char *aul_get_app_tep_resource_path(void)
{
	static char *path;

	return __get(&path, NULL, _TEP_RESOURCE_DIR, getuid(), __get_path_from_db);
}

API int aul_get_app_shared_data_path(char **path)
{
	return aul_get_app_shared_data_path_by_appid(NULL, path);
}

API const char *aul_get_app_shared_resource_path(void)
{
	static char *path;

	return __get(&path, NULL, _SHARED_RESOURCE_DIR, getuid(), __get_path_from_db);
}

API const char *aul_get_app_shared_trusted_path(void)
{
	static char *path;

	return __get(&path, NULL, _SHARED_TRUSTED_DIR, getuid(), __get_path);
}

API const char *aul_get_app_external_data_path(void)
{
	static char *path;

	return __get(&path, NULL, _DATA_DIR, getuid(), __get_external_path);
}

API const char *aul_get_app_external_cache_path(void)
{
	static char *path;

	return __get(&path, NULL, _CACHE_DIR, getuid(), __get_external_path);
}

API const char *aul_get_app_external_shared_data_path(void)
{
	static char *path;

	return __get(&path, NULL, _SHARED_DATA_DIR, getuid(),
			__get_external_path);
}

API const char *aul_get_app_specific_path(void)
{
	char appid[NAME_MAX];
	char pkgid[NAME_MAX];
	int ret;

	ret = aul_app_get_appid_bypid(getpid(), appid, sizeof(appid));
	if (ret != AUL_R_OK)
		return NULL;

	ret = __get_pkgid(pkgid, sizeof(pkgid), appid, getuid());
	if (ret != AUL_R_OK)
		return NULL;

	return __get_specific_path(pkgid, getuid());
}

API int aul_get_app_shared_data_path_by_appid(const char *appid, char **path)
{
	int ret;
	char *ret_path;

	if (path == NULL)
		return AUL_R_EINVAL;

	ret = __get_path(&ret_path, appid, _SHARED_DATA_DIR, getuid());
	if (ret != AUL_R_OK)
		return ret;

	ret = access(ret_path, F_OK);
	if (ret == 0) {
		*path = ret_path;
	} else {
		free(ret_path);
		return AUL_R_EREJECTED;
	}

	return AUL_R_OK;
}

API int aul_get_app_shared_resource_path_by_appid(const char *appid,
		char **path)
{
	if (appid == NULL || path == NULL)
		return AUL_R_EINVAL;

	return __get_path_from_db(path, appid, _SHARED_RESOURCE_DIR, getuid());
}

API int aul_get_app_shared_trusted_path_by_appid(const char *appid,
		char **path)
{
	if (appid == NULL || path == NULL)
		return AUL_R_EINVAL;

	return __get_path(path, appid, _SHARED_TRUSTED_DIR, getuid());
}

API int aul_get_app_external_shared_data_path_by_appid(const char *appid,
		char **path)
{
	if (appid == NULL || path == NULL)
		return AUL_R_EINVAL;

	return __get_external_path(path, appid, _SHARED_DATA_DIR, getuid());
}

API int aul_get_usr_app_shared_data_path_by_appid(const char *appid,
		char **path, uid_t uid)
{
	if (appid == NULL || path == NULL)
		return AUL_R_EINVAL;

	return __get_path_from_db(path, appid, _SHARED_DATA_DIR, uid);
}

API int aul_get_usr_app_shared_resource_path_by_appid(const char *appid,
		char **path, uid_t uid)
{
	if (appid == NULL || path == NULL)
		return AUL_R_EINVAL;

	return __get_path_from_db(path, appid, _SHARED_RESOURCE_DIR, uid);
}

API int aul_get_usr_app_shared_trusted_path_by_appid(const char *appid,
		char **path, uid_t uid)
{
	if (appid == NULL || path == NULL)
		return AUL_R_EINVAL;

	return __get_path_from_db(path, appid, _SHARED_TRUSTED_DIR, uid);
}

API int aul_get_usr_app_external_shared_data_path_by_appid(const char *appid,
		char **path, uid_t uid)
{
	if (appid == NULL || path == NULL)
		return AUL_R_EINVAL;

	return __get_external_path(path, appid, _SHARED_DATA_DIR, uid);
}
