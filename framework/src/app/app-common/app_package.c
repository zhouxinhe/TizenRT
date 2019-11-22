/*
 * Copyright (c) 2011 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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


#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <aul.h>
#include <pkgmgr-info.h>
#include <dlog.h>

#include <app_common.h>
#include <app_common_internal.h>

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "CAPI_APPFW_APPLICATION"

int app_get_package_app_name(const char *appid, char **name)
{
	char *name_token = NULL;

	if (appid == NULL)
		return app_error(APP_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	/* com.vendor.name -> name */
	name_token = strrchr(appid, '.');
	if (name_token == NULL)
		return app_error(APP_ERROR_INVALID_CONTEXT, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	name_token++;

	*name = strdup(name_token);
	if (*name == NULL)
		return app_error(APP_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	return APP_ERROR_NONE;
}

int app_get_id(char **id)
{
	static char id_buf[TIZEN_PATH_MAX] = {0, };
	int ret = -1;

	if (id == NULL)
		return app_error(APP_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (id_buf[0] == '\0') {
		ret = aul_app_get_appid_bypid(getpid(), id_buf, sizeof(id_buf));
		if (ret < 0)
			return app_error(APP_ERROR_INVALID_CONTEXT, __FUNCTION__, "failed to get the application ID"); /* LCOV_EXCL_LINE */
	}

	if (id_buf[0] == '\0')
		return app_error(APP_ERROR_INVALID_CONTEXT, __FUNCTION__, "failed to get the application ID"); /* LCOV_EXCL_LINE */

	*id = strdup(id_buf);
	if (*id == NULL)
		return app_error(APP_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	return APP_ERROR_NONE;
}

int app_get_package(char **package)
{
	return app_get_id(package);
}

int app_get_name(char **name)
{
	int retval = 0;
	char *appid = NULL;
	char *label = NULL;
	pkgmgrinfo_appinfo_h appinfo = NULL;

	if (name == NULL)
		return app_error(APP_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (app_get_id(&appid) != 0)
		return app_error(APP_ERROR_INVALID_CONTEXT, __FUNCTION__, "failed to get the package"); /* LCOV_EXCL_LINE */

	retval = pkgmgrinfo_appinfo_get_usr_appinfo(appid, getuid(), &appinfo);
	if (retval != 0) {
		/* LCOV_EXCL_START */
		free(appid);
		return app_error(APP_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
		/* LCOV_EXCL_STOP */
	}

	retval = pkgmgrinfo_appinfo_get_label(appinfo, &label);
	if (retval != 0) {
		/* LCOV_EXCL_START */
		free(appid);
		pkgmgrinfo_appinfo_destroy_appinfo(appinfo);
		return app_error(APP_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
		/* LCOV_EXCL_STOP */
	}

	*name = strdup(label);
	pkgmgrinfo_appinfo_destroy_appinfo(appinfo);
	free(appid);

	if (*name == NULL)
		return app_error(APP_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	return APP_ERROR_NONE;
}

int app_get_version(char **version)
{
	int retval = 0;
	char *appid = NULL;
	char *pkgid = NULL;
	char *pkg_version = NULL;
	pkgmgrinfo_pkginfo_h pkginfo = NULL;
	pkgmgrinfo_appinfo_h appinfo = NULL;

	if (version == NULL)
		return app_error(APP_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (app_get_id(&appid) != 0)
		return app_error(APP_ERROR_INVALID_CONTEXT, __FUNCTION__, "failed to get the package"); /* LCOV_EXCL_LINE */

	retval = pkgmgrinfo_appinfo_get_usr_appinfo(appid, getuid(), &appinfo);
	if (retval != 0) {
		/* LCOV_EXCL_START */
		free(appid);
		return app_error(APP_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
		/* LCOV_EXCL_STOP */
	}

	retval = pkgmgrinfo_appinfo_get_pkgid(appinfo, &pkgid);
	if (retval != 0) {
		/* LCOV_EXCL_START */
		free(appid);
		pkgmgrinfo_appinfo_destroy_appinfo(appinfo);
		return app_error(APP_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
		/* LCOV_EXCL_STOP */
	}

	retval = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &pkginfo);
	if (retval != 0) {
		/* LCOV_EXCL_START */
		free(appid);
		pkgmgrinfo_appinfo_destroy_appinfo(appinfo);
		return app_error(APP_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
		/* LCOV_EXCL_STOP */
	}

	retval = pkgmgrinfo_pkginfo_get_version(pkginfo, &pkg_version);
	if (retval != 0) {
		/* LCOV_EXCL_START */
		free(appid);
		pkgmgrinfo_appinfo_destroy_appinfo(appinfo);
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo);
		return app_error(APP_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
		/* LCOV_EXCL_STOP */
	}

	*version = strdup(pkg_version);
	pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo);
	pkgmgrinfo_appinfo_destroy_appinfo(appinfo);
	free(appid);

	if (*version == NULL)
		return app_error(APP_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	return APP_ERROR_NONE;
}

