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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <pkgmgr-info.h>
#include <package-manager.h>
#include <dlog.h>
#include <cynara-client.h>
#include <aul_svc.h>

#include "app_info.h"
#include "app_manager.h"
#include "app_manager_internal.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "TIZEN_N_APP_MANAGER"

#define SMACK_LABEL_LEN 255

struct app_info_s {
	char *app_id;
	pkgmgrinfo_appinfo_h pkg_app_info;
};

struct app_info_filter_s {
	pkgmgrinfo_appinfo_filter_h pkg_app_info_filter;
};

struct app_info_metadata_filter_s {
	pkgmgrinfo_appinfo_metadata_filter_h pkg_app_info_metadata_filter;
};

typedef struct _foreach_context_ {
	app_manager_app_info_cb callback;
	void *user_data;
} foreach_context_s;

typedef struct _foreach_metada_context_ {
	app_info_metadata_cb callback;
	void *user_data;
} foreach_metadata_context_s;

typedef struct _foreach_category_ {
	app_info_category_cb callback;
	void *user_data;
} foreach_category_context_s;

static int app_info_convert_str_property(const char *property, char **converted_property)
{
	if (property == NULL)
		return -1;

	if (strcmp(property, PACKAGE_INFO_PROP_APP_ID) == 0)
		*converted_property = PMINFO_APPINFO_PROP_APP_ID;
	else if (strcmp(property, PACKAGE_INFO_PROP_APP_TYPE) == 0)
		*converted_property = PMINFO_APPINFO_PROP_APP_TYPE;
	else if (strcmp(property, PACKAGE_INFO_PROP_APP_CATEGORY) == 0)
		*converted_property = PMINFO_APPINFO_PROP_APP_CATEGORY;
	else if (strcmp(property, PACKAGE_INFO_PROP_APP_INSTALLED_STORAGE) == 0)
		*converted_property = PMINFO_APPINFO_PROP_APP_INSTALLED_STORAGE;
	else if (strcmp(property, PACKAGE_INFO_PROP_APP_COMPONENT_TYPE) == 0)
		*converted_property = PMINFO_APPINFO_PROP_APP_COMPONENT;
	else
		return -1;

	return 0;
}

static int app_info_convert_bool_property(const char *property, char **converted_property)
{
	if (property == NULL)
		return -1;

	if (strcmp(property, PACKAGE_INFO_PROP_APP_NODISPLAY) == 0)
		*converted_property = PMINFO_APPINFO_PROP_APP_NODISPLAY;
	else if (strcmp(property, PACKAGE_INFO_PROP_APP_TASKMANAGE) == 0)
		*converted_property = PMINFO_APPINFO_PROP_APP_TASKMANAGE;
	else if (strcmp(property, PACKAGE_INFO_PROP_APP_DISABLED) == 0)
		*converted_property = PMINFO_APPINFO_PROP_APP_DISABLE;
	else
		return -1;

	return 0;
}

static int app_info_convert_app_component(pkgmgrinfo_app_component component, app_info_app_component_type_e *converted_component)
{
	if (component == PMINFO_UI_APP)
		*converted_component = APP_INFO_APP_COMPONENT_TYPE_UI_APP;
	else if (component == PMINFO_SVC_APP)
		*converted_component = APP_INFO_APP_COMPONENT_TYPE_SERVICE_APP;
	else if (component == PMINFO_WIDGET_APP)
		*converted_component = APP_INFO_APP_COMPONENT_TYPE_WIDGET_APP;
	else if (component == PMINFO_WATCH_APP)
		*converted_component = APP_INFO_APP_COMPONENT_TYPE_WATCH_APP;
	else
		return -1;

	return 0;
}

static int app_info_foreach_app_filter_cb(pkgmgrinfo_appinfo_h handle, void *user_data)
{
	int retval = 0;
	char *appid = NULL;
	app_info_h info = NULL;
	bool iteration_next = true;

	info = calloc(1, sizeof(struct app_info_s));
	if (info == NULL)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	foreach_context_s *foreach_context = user_data;
	if (handle == NULL || foreach_context == NULL) {
		/* LCOV_EXCL_START */
		free(info);
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
		/* LCOV_EXCL_STOP */
	}

	retval = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (retval < 0) {
		/* LCOV_EXCL_START */
		free(info);
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
		/* LCOV_EXCL_STOP */
	}

	info->app_id = strdup(appid);
	if (info->app_id == NULL) {
		/* LCOV_EXCL_START */
		if (info) {
			free(info);
			info = NULL;
		}
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
		/* LCOV_EXCL_STOP */
	}
	info->pkg_app_info = handle;

	iteration_next = foreach_context->callback(info, foreach_context->user_data);

	if (info->app_id) {
		free(info->app_id);
		info->app_id = NULL;
	}

	if (info) {
		free(info);
		info = NULL;
	}

	if (iteration_next == true)
		return PMINFO_R_OK;
	else
		return PMINFO_R_ERROR;
}

static int app_info_foreach_app_metadata_cb(const char *metadata_key, const char *metadata_value, void *user_data)
{
	foreach_metadata_context_s *foreach_context = user_data;
	bool iteration_next = true;

	if (metadata_value == NULL || foreach_context == NULL)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	iteration_next = foreach_context->callback(metadata_key, metadata_value, foreach_context->user_data);
	if (iteration_next == true)
		return PMINFO_R_OK;
	else
		return PMINFO_R_ERROR;
}

static int app_info_foreach_category_cb(const char *category_name, void *user_data)
{
	foreach_category_context_s *foreach_category = user_data;
	bool iteration_next = true;

	if (category_name == NULL || foreach_category == NULL)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	iteration_next = foreach_category->callback(category_name, foreach_category->user_data);
	if (iteration_next == true)
		return PMINFO_R_OK;
	else
		return PMINFO_R_ERROR;
}

static int app_info_foreach_app_info_cb(pkgmgrinfo_appinfo_h handle, void *cb_data)
{
	foreach_context_s *foreach_context = cb_data;
	app_info_h app_info = NULL;
	char *appid = NULL;
	int ret = 0;
	bool iteration_next = true;

	if (handle == NULL || foreach_context == NULL) {
		app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);
		return PMINFO_R_ERROR;
	}

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret != PMINFO_R_OK) {
		/* LCOV_EXCL_START */
		app_manager_error(APP_MANAGER_ERROR_NO_SUCH_APP, __FUNCTION__, NULL);
		return PMINFO_R_ERROR;
		/* LCOV_EXCL_STOP */
	}

	app_info = calloc(1, sizeof(struct app_info_s));
	if (app_info == NULL) {
		/* LCOV_EXCL_START */
		app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
		return PMINFO_R_ERROR;
		/* LCOV_EXCL_STOP */
	}

	app_info->app_id = strdup(appid);
	app_info->pkg_app_info = handle;
	iteration_next = foreach_context->callback(app_info, foreach_context->user_data);

	free(app_info->app_id);
	free(app_info);

	if (iteration_next == true)
		return PMINFO_R_OK;
	else
		return PMINFO_R_ERROR;
}

int app_info_foreach_app_info(app_manager_app_info_cb callback, void *user_data)
{
	foreach_context_s foreach_context = {
		.callback = callback,
		.user_data = user_data,
	};

	if (callback == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	pkgmgrinfo_appinfo_get_usr_installed_list(app_info_foreach_app_info_cb, getuid(), &foreach_context);

	return APP_MANAGER_ERROR_NONE;
}

static int _check_privilege(char *privilege)
{
	cynara *p_cynara;
	int fd;
	int ret;

	char client[SMACK_LABEL_LEN + 1] = {0,};
	char uid[10] = {0,};
	char *client_session = "";

	if (privilege == NULL) {
		LOGE("invalid parameter");
		return APP_MANAGER_ERROR_INVALID_PARAMETER;
	}

	ret = cynara_initialize(&p_cynara, NULL);
	if (ret != CYNARA_API_SUCCESS) {
		/* LCOV_EXCL_START */
		LOGE("cynara_initialize [%d] failed!", ret);
		return APP_MANAGER_ERROR_IO_ERROR;
		/* LCOV_EXCL_STOP */
	}

	fd = open("/proc/self/attr/current", O_RDONLY);
	if (fd < 0) {
		/* LCOV_EXCL_START */
		LOGE("open [%d] failed!", errno);
		ret = APP_MANAGER_ERROR_IO_ERROR;
		goto out;
		/* LCOV_EXCL_STOP */
	}

	ret = read(fd, client, SMACK_LABEL_LEN);
	if (ret < 0) {
		/* LCOV_EXCL_START */
		LOGE("read [%d] failed!", errno);
		close(fd);
		ret = APP_MANAGER_ERROR_IO_ERROR;
		goto out;
		/* LCOV_EXCL_STOP */
	}
	close(fd);
	snprintf(uid, 10, "%d", getuid());

	ret = cynara_check(p_cynara, client, client_session, uid, privilege);
	if (ret != CYNARA_API_ACCESS_ALLOWED) {
		LOGE("cynara access check [%d] failed!", ret);

		if (ret == CYNARA_API_ACCESS_DENIED)
			ret = APP_MANAGER_ERROR_PERMISSION_DENIED;
		else
			ret = APP_MANAGER_ERROR_IO_ERROR;

		goto out;
	}
	ret = APP_MANAGER_ERROR_NONE;

out:
	if (p_cynara)
		cynara_finish(p_cynara);

	return ret;
}

API int app_info_create(const char *app_id, app_info_h *app_info)
{
	pkgmgrinfo_pkginfo_h pkginfo = NULL;
	pkgmgrinfo_appinfo_h appinfo = NULL;
	app_info_h info = NULL;
	int retval = 0;
	char *main_appid = NULL;
	char *real_appid = NULL;

	if (app_id == NULL || app_info == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	info = calloc(1, sizeof(struct app_info_s));
	if (info == NULL)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	if (aul_svc_get_appid_by_alias_appid(app_id, &real_appid) ==
			AUL_SVC_RET_OK && real_appid != NULL) {
		/* LCOV_EXCL_START */
		retval = pkgmgrinfo_appinfo_get_usr_appinfo(real_appid,
				getuid(), &appinfo);
		free(real_appid);
		if (!retval) {
			info->app_id = strdup(app_id);
			info->pkg_app_info = appinfo;
			*app_info = info;
			return APP_MANAGER_ERROR_NONE;
		}
		/* LCOV_EXCL_STOP */
	}
	retval = pkgmgrinfo_appinfo_get_usr_appinfo(app_id, getuid(), &appinfo);
	if (!retval) {
		info->app_id = strdup(app_id);
		info->pkg_app_info = appinfo;
		*app_info = info;
		return APP_MANAGER_ERROR_NONE;
	}

	retval = pkgmgrinfo_pkginfo_get_usr_pkginfo(app_id, getuid(), &pkginfo);
	if (retval < 0) {
		free(info);
		return app_manager_error(APP_MANAGER_ERROR_NO_SUCH_APP, __FUNCTION__, NULL);
	}

	retval = pkgmgrinfo_pkginfo_get_mainappid(pkginfo, &main_appid);
	if (retval < 0) {
		free(info);
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo);
		return app_manager_error(APP_MANAGER_ERROR_NO_SUCH_APP, __FUNCTION__, NULL);
	}
	if (pkgmgrinfo_appinfo_get_usr_appinfo(main_appid, getuid(), &appinfo)) {
		free(info);
		pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo);
		return app_manager_error(APP_MANAGER_ERROR_NO_SUCH_APP, __FUNCTION__, NULL);
	}

	info->app_id = strdup(main_appid);
	info->pkg_app_info = appinfo;
	*app_info = info;

	pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo);

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_destroy(app_info_h app_info)
{
	if (app_info == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (app_info->app_id) {
		free(app_info->app_id);
		app_info->app_id = NULL;
	}

	pkgmgrinfo_appinfo_destroy_appinfo(app_info->pkg_app_info);
	free(app_info);
	return APP_MANAGER_ERROR_NONE;
}

API int app_info_get_app_id(app_info_h app_info, char **app_id)
{
	char *app_id_dup = NULL;

	if (app_info == NULL || app_id == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (app_info->app_id == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	app_id_dup = strdup(app_info->app_id);
	if (app_id_dup == NULL)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	*app_id = app_id_dup;

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_get_exec(app_info_h app_info, char **exec)
{
	char *val = NULL;
	char *app_exec_dup = NULL;
	int ret = -1;

	if (app_info == NULL || exec == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	ret = pkgmgrinfo_appinfo_get_exec(app_info->pkg_app_info, &val);
	if (ret != PMINFO_R_OK || val == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	app_exec_dup = strdup(val);
	if (app_exec_dup == NULL)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	*exec = app_exec_dup;

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_get_label(app_info_h app_info, char **label)
{
	char *val = NULL;
	char *app_label_dup = NULL;
	int ret = 0;

	if (app_info == NULL || label == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	ret = pkgmgrinfo_appinfo_get_label(app_info->pkg_app_info, &val);
	if (ret < 0 || val == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	app_label_dup = strdup(val);
	if (app_label_dup == NULL)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	*label = app_label_dup;

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_get_localed_label(const char *app_id, const char *locale, char **label)
{
	char *val = NULL;
	char *app_label_dup = NULL;

	if (app_id == NULL || locale == NULL || label == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (pkgmgrinfo_appinfo_usr_get_localed_label(app_id, locale, getuid(), &val))
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	app_label_dup = strdup(val);
	if (app_label_dup == NULL) {
		/* LCOV_EXCL_START */
		if (val) {
			free(val);
			val = NULL;
		}
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
		/* LCOV_EXCL_STOP */
	}

	*label = app_label_dup;
	free(val);

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_get_icon(app_info_h app_info, char **path)
{
	char *val = NULL;
	char *app_icon_dup = NULL;
	int ret = -1;

	if (app_info == NULL || path == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	ret = pkgmgrinfo_appinfo_get_icon(app_info->pkg_app_info, &val);
	if (ret != PMINFO_R_OK || val == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	app_icon_dup = strdup(val);
	if (app_icon_dup == NULL)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	*path = app_icon_dup;

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_get_package(app_info_h app_info, char **package)
{
	char *val = NULL;
	char *app_package_dup = NULL;
	int ret = 0;

	if (app_info == NULL || package == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	ret = pkgmgrinfo_appinfo_get_pkgname(app_info->pkg_app_info, &val);
	if (ret < 0)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */
	if (val == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	app_package_dup = strdup(val);
	if (app_package_dup == NULL)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	*package = app_package_dup;

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_get_type(app_info_h app_info, char **type)
{
	char *val = NULL;
	char *app_type_dup = NULL;
	int ret = 0;

	if (app_info == NULL || type == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	ret = pkgmgrinfo_appinfo_get_apptype(app_info->pkg_app_info, &val);
	if (ret < 0)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */
	if (val == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	app_type_dup = strdup(val);
	if (app_type_dup == NULL)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	*type = app_type_dup;

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_get_app_component_type(app_info_h app_info, app_info_app_component_type_e *type)
{
	pkgmgrinfo_app_component comp_val;
	app_info_app_component_type_e converted_comp_val;
	int ret = 0;

	if (app_info == NULL || type == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	ret = pkgmgrinfo_appinfo_get_component(app_info->pkg_app_info, &comp_val);
	if (ret < 0)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);

	ret = app_info_convert_app_component(comp_val, &converted_comp_val);
	if (ret < 0)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);

	*type = converted_comp_val;

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_foreach_metadata(app_info_h app_info, app_info_metadata_cb callback, void *user_data)
{
	int retval = 0;

	if (app_info == NULL || callback == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	foreach_metadata_context_s foreach_context = {
		.callback = callback,
		.user_data = user_data,
	};

	retval = pkgmgrinfo_appinfo_foreach_metadata(app_info->pkg_app_info, app_info_foreach_app_metadata_cb, &foreach_context);
	if (retval < 0)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_is_nodisplay(app_info_h app_info, bool *nodisplay)
{
	bool val;

	if (app_info == NULL || nodisplay == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (pkgmgrinfo_appinfo_is_nodisplay(app_info->pkg_app_info, &val) < 0)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	*nodisplay = val;
	return APP_MANAGER_ERROR_NONE;
}

API int app_info_is_enabled(app_info_h app_info, bool *enabled)
{
	bool val;

	if (app_info == NULL || enabled == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (pkgmgrinfo_appinfo_is_enabled(app_info->pkg_app_info, &val) < 0)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	*enabled = val;
	return APP_MANAGER_ERROR_NONE;

}

API int app_info_is_equal(app_info_h lhs, app_info_h rhs, bool *equal)
{
	if (lhs == NULL || rhs == NULL || equal == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (!strcmp(lhs->app_id, rhs->app_id))
		*equal = true;
	else
		*equal = false;

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_is_onboot(app_info_h app_info, bool *onboot)
{
	bool val;

	if (app_info == NULL || onboot == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (pkgmgrinfo_appinfo_is_onboot(app_info->pkg_app_info, &val) < 0)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	*onboot = val;
	return APP_MANAGER_ERROR_NONE;
}

API int app_info_is_preload(app_info_h app_info, bool *preload)
{
	bool val;

	if (app_info == NULL || preload == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (pkgmgrinfo_appinfo_is_preload(app_info->pkg_app_info, &val) < 0)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	*preload = val;
	return APP_MANAGER_ERROR_NONE;
}

API int app_info_clone(app_info_h *clone, app_info_h app_info)
{
	app_info_h info;

	if (clone == NULL || app_info == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	info = calloc(1, sizeof(struct app_info_s));
	if (info == NULL)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	info->app_id = strdup(app_info->app_id);
	if (info->app_id == NULL) {
		/* LCOV_EXCL_START */
		free(info);
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
		/* LCOV_EXCL_STOP */
	}

	if (pkgmgrinfo_appinfo_clone_appinfo(app_info->pkg_app_info, &(info->pkg_app_info)) < 0) {
		/* LCOV_EXCL_START */
		free(info->app_id);
		free(info);
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
		/* LCOV_EXCL_STOP */
	}

	*clone = info;

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_foreach_category(app_info_h app_info, app_info_category_cb callback, void *user_data)
{
	int retval;
	if (app_info == NULL || callback == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	retval = _check_privilege(PRIVILEGE_PACKAGE_MANAGER_ADMIN);
	if (retval != APP_MANAGER_ERROR_NONE)
		return app_manager_error(APP_MANAGER_ERROR_PERMISSION_DENIED, __FUNCTION__, NULL);

	foreach_category_context_s foreach_category = {
		.callback = callback,
		.user_data = user_data,
	};

	retval = pkgmgrinfo_appinfo_foreach_category(app_info->pkg_app_info, app_info_foreach_category_cb, &foreach_category);
	if (retval != PMINFO_R_OK)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_filter_create(app_info_filter_h *handle)
{
	int retval = 0;
	app_info_filter_h filter_created = NULL;
	pkgmgrinfo_appinfo_filter_h filter_h = NULL;

	if (handle == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	retval = pkgmgrinfo_appinfo_filter_create(&filter_h);
	if (retval < 0)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	filter_created = calloc(1, sizeof(struct app_info_filter_s));
	if (filter_created == NULL) {
		/* LCOV_EXCL_START */
		free(filter_h);
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
		/* LCOV_EXCL_STOP */
	}

	filter_created->pkg_app_info_filter = filter_h;

	*handle = filter_created;

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_filter_destroy(app_info_filter_h handle)
{
	int retval = 0;

	if (handle == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	retval = pkgmgrinfo_appinfo_filter_destroy(handle->pkg_app_info_filter);
	if (retval < 0)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	free(handle);
	return APP_MANAGER_ERROR_NONE;
}

API int app_info_filter_add_bool(app_info_filter_h handle, const char *property, const bool value)
{
	int retval = 0;
	char *converted_property = NULL;

	if ((handle == NULL) || (property == NULL))
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	retval = app_info_convert_bool_property(property, &converted_property);
	if (retval < 0)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	retval = pkgmgrinfo_appinfo_filter_add_bool(handle->pkg_app_info_filter, converted_property, value);
	if (retval < 0)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_filter_add_string(app_info_filter_h handle, const char *property, const char *value)
{
	int retval = 0;
	char *converted_property = NULL;

	if ((handle == NULL) || (property == NULL))
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	retval = app_info_convert_str_property(property, &converted_property);
	if (retval < 0)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	retval = pkgmgrinfo_appinfo_filter_add_string(handle->pkg_app_info_filter, converted_property, value);
	if (retval < 0)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_filter_count_appinfo(app_info_filter_h handle, int *count)
{
	int retval = 0;

	if ((handle == NULL) || (count == NULL))
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	retval = pkgmgrinfo_appinfo_filter_count(handle->pkg_app_info_filter, count);
	if (retval < 0)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_filter_foreach_appinfo(app_info_filter_h handle, app_info_filter_cb callback, void *user_data)
{
	int retval = 0;

	foreach_context_s foreach_context = {
		.callback = callback,
		.user_data = user_data,
	};

	if ((handle == NULL) || (callback == NULL))
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	retval = pkgmgrinfo_appinfo_usr_filter_foreach_appinfo(handle->pkg_app_info_filter, app_info_foreach_app_filter_cb, &foreach_context, getuid());
	if (retval < 0)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_metadata_filter_create(app_info_metadata_filter_h *handle)
{
	int retval = 0;
	app_info_metadata_filter_h filter_created = NULL;
	pkgmgrinfo_appinfo_metadata_filter_h filter_h = NULL;

	if (handle == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	filter_created = calloc(1, sizeof(struct app_info_metadata_filter_s));
	if (filter_created == NULL)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	retval = pkgmgrinfo_appinfo_metadata_filter_create(&filter_h);
	if (retval < 0) {
		/* LCOV_EXCL_START */
		free(filter_created);
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL);
		/* LCOV_EXCL_STOP */
	}

	filter_created->pkg_app_info_metadata_filter = filter_h;

	*handle = filter_created;

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_metadata_filter_destroy(app_info_metadata_filter_h handle)
{
	int retval = 0;

	if (handle == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	retval = pkgmgrinfo_appinfo_metadata_filter_destroy(handle->pkg_app_info_metadata_filter);
	if (retval < 0)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	free(handle);
	return APP_MANAGER_ERROR_NONE;
}

API int app_info_metadata_filter_add(app_info_metadata_filter_h handle, const char *key, const char *value)
{
	int retval = 0;

	if ((handle == NULL) || (key == NULL))
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	retval = pkgmgrinfo_appinfo_metadata_filter_add(handle->pkg_app_info_metadata_filter, key, value);
	if (retval < 0)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	return APP_MANAGER_ERROR_NONE;
}

API int app_info_metadata_filter_foreach(app_info_metadata_filter_h handle, app_info_filter_cb callback, void *user_data)
{
	int retval = 0;

	foreach_context_s foreach_context = {
		.callback = callback,
		.user_data = user_data,
	};

	if (handle == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (callback == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	retval = pkgmgrinfo_appinfo_usr_metadata_filter_foreach(handle->pkg_app_info_metadata_filter, app_info_foreach_app_filter_cb, &foreach_context, getuid());
	if (retval < 0)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	return APP_MANAGER_ERROR_NONE;
}

