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
#include <pthread.h>

#include <glib.h>

#include <aul.h>
#include <aul_window.h>
#include <dlog.h>
#include <pkgmgr-info.h>

#include "app_context.h"
#include "app_manager.h"
#include "app_manager_internal.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "CAPI_APPFW_APP_MANAGER"

#define APPID_MAX 128

static int app_context_create(const char *app_id, pid_t pid, const char *pkg_id, app_state_e app_state, bool is_sub_app, const char *instance_id, app_context_h *app_context);

struct app_context_s {
	char *app_id;
	pid_t pid;
	char *pkg_id;
	app_state_e app_state;
	bool is_sub_app;
	char *instance_id;
};

typedef struct _foreach_context_ {
	app_manager_app_context_cb callback;
	void *user_data;
	bool iteration;
} foreach_context_s;

typedef struct _retrieval_context_ {
	const char *app_id;
	pid_t pid;
	char *pkg_id;
	app_state_e app_state;
	bool is_sub_app;
	bool matched;
	const char *instance_id;
} retrieval_context_s;

struct status_listen_info {
	status_listen_h handle;
	char *appid;
	app_manager_app_context_status_cb callback;
	void *user_data;
};

static GList *status_listen_list;

static app_state_e app_context_get_app_status(int status)
{
	app_state_e app_state;

	switch (status) {
	case STATUS_VISIBLE:
		app_state = APP_STATE_FOREGROUND;
		break;
	case STATUS_LAUNCHING:
	case STATUS_BG:
		app_state = APP_STATE_BACKGROUND;
		break;
	case STATUS_SERVICE:
		app_state = APP_STATE_SERVICE;
		break;
	case STATUS_TERMINATE:
		app_state = APP_STATE_TERMINATED;
		break;
	default:
		app_state = APP_STATE_UNDEFINED;
		break;
	}

	return app_state;
}

static int app_context_foreach_app_context_cb(const aul_app_info *aul_app_context, void *cb_data)
{
	foreach_context_s *foreach_context = cb_data;
	app_context_h app_context;
	app_state_e app_state;
	bool is_sub_app = false;

	if (foreach_context == NULL) {
		app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */
		return 0;
	}

	if (foreach_context->iteration == true) {
		app_state = app_context_get_app_status(aul_app_context->status);

		if (aul_app_context->is_sub_app)
			is_sub_app = true;

		if (app_context_create(aul_app_context->appid,
					aul_app_context->pid,
					aul_app_context->pkgid,
					app_state,
					is_sub_app,
					aul_app_context->instance_id,
					&app_context) == APP_MANAGER_ERROR_NONE) {
			foreach_context->iteration = foreach_context->callback(app_context, foreach_context->user_data);
			app_context_destroy(app_context);
		}
	}

	return 0;
}

int app_context_foreach_app_context(app_manager_app_context_cb callback, void *user_data)
{
	foreach_context_s foreach_context = {
		.callback = callback,
		.user_data = user_data,
		.iteration = true
	};

	if (callback == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (aul_app_get_running_app_info(app_context_foreach_app_context_cb, &foreach_context) != AUL_R_OK)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	return APP_MANAGER_ERROR_NONE;
}

static int app_context_foreach_running_app_context_cb(const aul_app_info *aul_app_context, void *cb_data)
{
	foreach_context_s *foreach_context = cb_data;
	app_context_h app_context;
	app_state_e app_state;
	bool is_sub_app = false;

	if (foreach_context == NULL) {
		app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */
		return 0;
	}

	if (foreach_context->iteration == true) {
		app_state = app_context_get_app_status(aul_app_context->status);

		if (aul_app_context->is_sub_app)
			is_sub_app = true;

		if (app_context_create(aul_app_context->appid,
					aul_app_context->pid,
					aul_app_context->pkgid,
					app_state,
					is_sub_app,
					aul_app_context->instance_id,
					&app_context) == APP_MANAGER_ERROR_NONE) {
			foreach_context->iteration = foreach_context->callback(app_context, foreach_context->user_data);
			app_context_destroy(app_context);
		}
	}

	return 0;
}

int app_context_foreach_running_app_context(app_manager_app_context_cb callback, void *user_data)
{
	int ret;
	foreach_context_s foreach_context = {
		.callback = callback,
		.user_data = user_data,
		.iteration = true
	};

	if (callback == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	ret = aul_app_get_all_running_app_info(app_context_foreach_running_app_context_cb, &foreach_context);
	if (ret != AUL_R_OK)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	return APP_MANAGER_ERROR_NONE;
}

static int app_context_retrieve_app_context(const aul_app_info *aul_app_context, void *cb_data)
{
	retrieval_context_s *retrieval_context = cb_data;
	app_state_e app_state;

	if (aul_app_context != NULL && retrieval_context != NULL && retrieval_context->matched == false) {
		if (retrieval_context->instance_id && retrieval_context->app_id &&
				!strcmp(aul_app_context->instance_id, retrieval_context->instance_id) &&
				!strcmp(aul_app_context->appid, retrieval_context->app_id)) {
			app_state = app_context_get_app_status(aul_app_context->status);

			retrieval_context->pid = aul_app_context->pid;
			retrieval_context->pkg_id = strdup(aul_app_context->pkgid);
			retrieval_context->app_state = app_state;
			if (aul_app_context->is_sub_app)
				retrieval_context->is_sub_app = true;
			retrieval_context->matched = true;
		} else if (retrieval_context->instance_id == NULL && retrieval_context->app_id &&
				!strcmp(aul_app_context->appid, retrieval_context->app_id)) {
			app_state = app_context_get_app_status(aul_app_context->status);

			retrieval_context->pid = aul_app_context->pid;
			retrieval_context->pkg_id = strdup(aul_app_context->pkgid);
			retrieval_context->app_state = app_state;
			if (aul_app_context->is_sub_app)
				retrieval_context->is_sub_app = true;
			retrieval_context->matched = true;
		} else if (retrieval_context->pid > 0 && retrieval_context->pid == aul_app_context->pid) {
			app_state = app_context_get_app_status(aul_app_context->status);

			retrieval_context->app_id = strdup(aul_app_context->appid);
			retrieval_context->pkg_id = strdup(aul_app_context->pkgid);
			retrieval_context->app_state = app_state;
			if (aul_app_context->is_sub_app)
				retrieval_context->is_sub_app = true;
			retrieval_context->matched = true;
		}
	}

	return 0;
}

int app_context_get_app_context(const char *app_id, app_context_h *app_context)
{
	int ret;
	retrieval_context_s retrieval_context =  {
		.app_id = app_id,
		.pid = 0,
		.pkg_id = NULL,
		.app_state = APP_STATE_UNDEFINED,
		.is_sub_app = false,
		.matched = false,
		.instance_id = NULL
	};

	if (app_id == NULL || app_context == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (aul_app_is_running(app_id) == 0)
		return app_manager_error(APP_MANAGER_ERROR_NO_SUCH_APP, __FUNCTION__, NULL);

	aul_app_get_running_app_info(app_context_retrieve_app_context, &retrieval_context);

	if (retrieval_context.matched == false)
		return app_manager_error(APP_MANAGER_ERROR_NO_SUCH_APP, __FUNCTION__, NULL);

	ret = app_context_create(retrieval_context.app_id,
					retrieval_context.pid,
					retrieval_context.pkg_id,
					retrieval_context.app_state,
					retrieval_context.is_sub_app,
					retrieval_context.instance_id,
					app_context);
	free(retrieval_context.pkg_id);

	return ret;
}

static int app_context_create(const char *app_id, pid_t pid, const char *pkg_id, app_state_e app_state, bool is_sub_app, const char *instance_id, app_context_h *app_context)
{
	app_context_h app_context_created;

	if (app_id == NULL || pid <= 0 || pkg_id == NULL || app_context == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	app_context_created = calloc(1, sizeof(struct app_context_s));
	if (app_context_created == NULL)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	app_context_created->app_id = strdup(app_id);
	if (app_context_created->app_id == NULL) {
		free(app_context_created);
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */
	}

	app_context_created->pkg_id = strdup(pkg_id);
	if (app_context_created->pkg_id == NULL) {
		/* LCOV_EXCL_START */
		free(app_context_created->app_id);
		free(app_context_created);
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
		/* LCOV_EXCL_STOP */
	}

	if (instance_id) {
		app_context_created->instance_id = strdup(instance_id);
		if (app_context_created->instance_id == NULL) {
			/* LCOV_EXCL_START */
			free(app_context_created->pkg_id);
			free(app_context_created->app_id);
			free(app_context_created);
			return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
			/* LCOV_EXCL_STOP */
		}
	}

	app_context_created->pid = pid;
	app_context_created->app_state = app_state;
	app_context_created->is_sub_app = is_sub_app;

	*app_context = app_context_created;

	return APP_MANAGER_ERROR_NONE;
}

API int app_context_destroy(app_context_h app_context)
{
	if (app_context == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	free(app_context->app_id);
	free(app_context->pkg_id);
	free(app_context->instance_id);
	free(app_context);

	return APP_MANAGER_ERROR_NONE;
}

API int app_context_get_package(app_context_h app_context, char **package)
{
	dlog_print(DLOG_WARN, LOG_TAG, "DEPRECATION WARNING: app_context_get_package() is deprecated and will be removed from next release. Use app_context_get_app_id() instead.");
	/* TODO: this function must be deprecated */
	return app_context_get_app_id(app_context, package);
}


API int app_context_get_app_id(app_context_h app_context, char **app_id)
{
	char *app_id_dup;

	if (app_context == NULL || app_id == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	app_id_dup = strdup(app_context->app_id);
	if (app_id_dup == NULL)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	*app_id = app_id_dup;

	return APP_MANAGER_ERROR_NONE;
}

API int app_context_get_pid(app_context_h app_context, pid_t *pid)
{
	if (app_context == NULL || pid == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	*pid = app_context->pid;

	return APP_MANAGER_ERROR_NONE;
}

API int app_context_get_package_id(app_context_h app_context, char **pkg_id)
{
	char *pkg_id_dup;

	if (app_context == NULL || pkg_id == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	pkg_id_dup = strdup(app_context->pkg_id);
	if (pkg_id_dup == NULL)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	*pkg_id = pkg_id_dup;

	return APP_MANAGER_ERROR_NONE;
}

API int app_context_get_app_state(app_context_h app_context, app_state_e *state)
{
	if (app_context == NULL || state == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	*state = app_context->app_state;

	return APP_MANAGER_ERROR_NONE;
}

API int app_context_is_terminated(app_context_h app_context, bool *terminated)
{
	char appid[APPID_MAX] = {0, };

	if (app_context == NULL || terminated == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (aul_app_is_running(app_context->app_id) == 1) {
		*terminated = false;
	} else {
		if (aul_app_get_appid_bypid(app_context->pid, appid, sizeof(appid)) == AUL_R_OK)
			*terminated = false;
		else
			*terminated = true;
	}

	return APP_MANAGER_ERROR_NONE;
}

API int app_context_is_equal(app_context_h lhs, app_context_h rhs, bool *equal)
{
	if (lhs == NULL || rhs == NULL || equal == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (!strcmp(lhs->app_id, rhs->app_id) && lhs->pid == rhs->pid)
		*equal = true;
	else
		*equal = false;

	return APP_MANAGER_ERROR_NONE;
}

API int app_context_is_sub_app(app_context_h app_context, bool *is_sub_app)
{
	if (app_context == NULL || is_sub_app == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	*is_sub_app = app_context->is_sub_app;

	return APP_MANAGER_ERROR_NONE;
}

API int app_context_clone(app_context_h *clone, app_context_h app_context)
{
	int retval;

	if (clone == NULL || app_context == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	retval = app_context_create(app_context->app_id,
					app_context->pid,
					app_context->pkg_id,
					app_context->app_state,
					app_context->is_sub_app,
					app_context->instance_id,
					clone);
	if (retval != APP_MANAGER_ERROR_NONE)
		return app_manager_error(retval, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	return APP_MANAGER_ERROR_NONE;
}

typedef struct _event_cb_context_ {
	GHashTable *pid_table;
	app_manager_app_context_event_cb callback;
	void *user_data;
} event_cb_context_s;

static pthread_mutex_t event_cb_context_mutex = PTHREAD_MUTEX_INITIALIZER;
static event_cb_context_s *event_cb_context = NULL;

static void app_context_lock_event_cb_context()
{
	pthread_mutex_lock(&event_cb_context_mutex);
}

static void app_context_unlock_event_cb_context()
{
	pthread_mutex_unlock(&event_cb_context_mutex);
}

static bool app_context_load_all_app_context_cb_locked(app_context_h app_context, void *user_data)
{
	app_context_h app_context_cloned;

	if (app_context_clone(&app_context_cloned, app_context) == APP_MANAGER_ERROR_NONE) {
		SECURE_LOGI("[%s] app_id(%s), pid(%d)", __FUNCTION__, app_context->app_id, app_context->pid);

		if (event_cb_context != NULL && event_cb_context->pid_table != NULL) {
			g_hash_table_insert(event_cb_context->pid_table, GINT_TO_POINTER(&(app_context_cloned->pid)), app_context_cloned);
		} else {
			/* LCOV_EXCL_START */
			app_context_destroy(app_context_cloned);
			app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, "invalid callback context");
			/* LCOV_EXCL_STOP */
		}
	}

	return true;
}

static void app_context_pid_table_entry_destroyed_cb(void *data)
{
	app_context_h app_context = data;

	if (app_context != NULL)
		app_context_destroy(app_context);
}

static int app_context_get_pkgid_by_appid(const char *app_id, char **pkg_id)
{
	pkgmgrinfo_appinfo_h appinfo;
	char *pkg_id_dup;

	if (app_id == NULL || pkg_id == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (pkgmgrinfo_appinfo_get_usr_appinfo(app_id, getuid(), &appinfo) < 0)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, "fail to get appinfo"); /* LCOV_EXCL_LINE */

	if (pkgmgrinfo_appinfo_get_pkgid(appinfo, &pkg_id_dup) < 0) {
		/* LCOV_EXCL_START */
		pkgmgrinfo_appinfo_destroy_appinfo(appinfo);
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, "fail to get pkgid");
		/* LCOV_EXCL_STOP */
	}

	*pkg_id = strdup(pkg_id_dup);

	pkgmgrinfo_appinfo_destroy_appinfo(appinfo);
	return APP_MANAGER_ERROR_NONE;
}

static int app_context_launched_event_cb(pid_t pid, const char *app_id, void *data)
{
	app_context_h app_context = NULL;
	char *pkg_id = NULL;

	if (pid < 0 || app_id == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	if (app_context_get_pkgid_by_appid(app_id, &pkg_id) < 0)
		return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, "no such pkg_id"); /* LCOV_EXCL_LINE */

	app_context_lock_event_cb_context();

	if (app_context_create(app_id, pid, pkg_id, APP_STATE_UNDEFINED, false, NULL, &app_context) == APP_MANAGER_ERROR_NONE) {
		if (event_cb_context != NULL && event_cb_context->pid_table != NULL) {
			g_hash_table_insert(event_cb_context->pid_table, GINT_TO_POINTER(&(app_context->pid)), app_context);
			event_cb_context->callback(app_context, APP_CONTEXT_EVENT_LAUNCHED, event_cb_context->user_data);
		} else {
			/* LCOV_EXCL_START */
			app_context_destroy(app_context);
			app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, "invalid callback context");
			/* LCOV_EXCL_STOP */
		}
	}

	app_context_unlock_event_cb_context();

	free(pkg_id);
	return 0;
}

static int app_context_terminated_event_cb(pid_t pid, void *data)
{
	app_context_h app_context;
	int lookup_key = pid;

	app_context_lock_event_cb_context();

	if (event_cb_context != NULL && event_cb_context->pid_table != NULL) {
		app_context = g_hash_table_lookup(event_cb_context->pid_table, GINT_TO_POINTER(&lookup_key));

		if (app_context != NULL) {
			event_cb_context->callback(app_context, APP_CONTEXT_EVENT_TERMINATED, event_cb_context->user_data);
			g_hash_table_remove(event_cb_context->pid_table, GINT_TO_POINTER(&(app_context->pid)));
		}
	} else {
		app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, "invalid callback context"); /* LCOV_EXCL_LINE */
	}

	app_context_unlock_event_cb_context();

	return 0;
}

int app_context_set_event_cb(app_manager_app_context_event_cb callback, void *user_data)
{
	if (callback == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	app_context_lock_event_cb_context();

	if (event_cb_context == NULL) {
		event_cb_context = calloc(1, sizeof(event_cb_context_s));

		if (event_cb_context == NULL) {
			/* LCOV_EXCL_START */
			app_context_unlock_event_cb_context();
			return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);
			/* LCOV_EXCL_STOP */
		}

		event_cb_context->pid_table = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, app_context_pid_table_entry_destroyed_cb);
		if (event_cb_context->pid_table == NULL) {
			/* LCOV_EXCL_START */
			free(event_cb_context);
			event_cb_context = NULL;
			app_context_unlock_event_cb_context();
			return app_manager_error(APP_MANAGER_ERROR_IO_ERROR, __FUNCTION__, "failed to initialize pid-table");
			/* LCOV_EXCL_STOP */
		}

		app_context_foreach_app_context(app_context_load_all_app_context_cb_locked, NULL);

		aul_listen_app_dead_signal(app_context_terminated_event_cb, NULL);
		aul_listen_app_launch_signal_v2(app_context_launched_event_cb, NULL);

	}

	event_cb_context->callback = callback;
	event_cb_context->user_data = user_data;

	app_context_unlock_event_cb_context();

	return APP_MANAGER_ERROR_NONE;
}

void app_context_unset_event_cb(void)
{
	app_context_lock_event_cb_context();

	if (event_cb_context != NULL) {
		aul_listen_app_dead_signal(NULL, NULL);
		aul_listen_app_launch_signal_v2(NULL, NULL);

		g_hash_table_destroy(event_cb_context->pid_table);
		free(event_cb_context);
		event_cb_context = NULL;
	}

	app_context_unlock_event_cb_context();
}

static struct status_listen_info *__find_status_listen_info(app_manager_app_context_status_cb callback, const char *appid)
{
	struct status_listen_info *info;
	GList *iter;

	iter = g_list_first(status_listen_list);
	while (iter) {
		info = (struct status_listen_info *)iter->data;
		if (info && info->callback == callback && !strcmp(info->appid, appid))
			return info;
		iter = g_list_next(iter);
	}

	return NULL;
}

static struct status_listen_info *__create_status_listen_info(app_manager_app_context_status_cb callback, const char *appid, void *user_data)
{
	struct status_listen_info *info;

	info = calloc(1, sizeof(struct status_listen_info));
	if (info == NULL) {
		/* LCOV_EXCL_START */
		LOGE("Out of memory");
		return NULL;
		/* LCOV_EXCL_STOP */
	}

	info->appid = strdup(appid);
	if (info->appid == NULL) {
		/* LCOV_EXCL_START */
		LOGE("Out of memory");
		free(info);
		return NULL;
		/* LCOV_EXCL_STOP */
	}

	info->callback = callback;
	info->user_data = user_data;

	return info;
}

static void __destroy_status_listen_info(struct status_listen_info *info)
{
	if (info == NULL)
		return;

	if (info->appid)
		free(info->appid);
	free(info);
}

static int app_context_status_cb(aul_app_info *aul_app_context, int ctx_status, void *data)
{
	struct status_listen_info *info = (struct status_listen_info *)data;
	app_context_h app_context = NULL;
	app_context_status_e context_status;
	int ret;

	if (ctx_status == STATUS_TERMINATE)
		context_status = APP_CONTEXT_STATUS_TERMINATED;
	else
		context_status = APP_CONTEXT_STATUS_LAUNCHED;

	ret = app_context_create(aul_app_context->appid,
			aul_app_context->pid,
			aul_app_context->pkgid,
			app_context_get_app_status(aul_app_context->status),
			aul_app_context->is_sub_app,
			aul_app_context->instance_id,
			&app_context);
	if (ret != APP_MANAGER_ERROR_NONE)
		return app_manager_error(ret, __FUNCTION__, NULL);

	info->callback(app_context, context_status, info->user_data);
	app_context_destroy(app_context);

	return APP_MANAGER_ERROR_NONE;
}

int app_context_set_status_cb(app_manager_app_context_status_cb callback, const char *appid, void *user_data)
{
	int ret;
	struct status_listen_info *info;

	if (callback == NULL || appid == NULL)
		return APP_MANAGER_ERROR_INVALID_PARAMETER;

	info = __find_status_listen_info(callback, appid);
	if (info) {
		info->user_data = user_data;
		return APP_MANAGER_ERROR_NONE;
	}

	info = __create_status_listen_info(callback, appid, user_data);
	if (info == NULL)
		return APP_MANAGER_ERROR_OUT_OF_MEMORY;

	ret = aul_listen_app_status(appid, app_context_status_cb, info, &info->handle);
	if (ret != AUL_R_OK) {
		/* LCOV_EXCL_START */
		__destroy_status_listen_info(info);
		if (ret == AUL_R_EINVAL)
			return APP_MANAGER_ERROR_INVALID_PARAMETER;

		return APP_MANAGER_ERROR_IO_ERROR;
		/* LCOV_EXCL_STOP */
	}

	status_listen_list = g_list_append(status_listen_list, info);

	return APP_MANAGER_ERROR_NONE;
}

int app_context_get_app_context_by_instance_id(const char *app_id, const char *instance_id, app_context_h *app_context)
{
	int ret;
	retrieval_context_s retrieval_context = {
		.app_id = app_id,
		.pid = 0,
		.pkg_id = NULL,
		.app_state = APP_STATE_UNDEFINED,
		.is_sub_app = false,
		.matched = false,
		.instance_id = instance_id
	};

	if (app_id == NULL || instance_id == NULL || app_context == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	aul_app_get_running_app_instance_info(app_context_retrieve_app_context, &retrieval_context);
	if (retrieval_context.matched == false)
		return app_manager_error(APP_MANAGER_ERROR_NO_SUCH_APP, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	ret = app_context_create(retrieval_context.app_id,
			retrieval_context.pid,
			retrieval_context.pkg_id,
			retrieval_context.app_state,
			retrieval_context.is_sub_app,
			retrieval_context.instance_id,
			app_context);
	free(retrieval_context.pkg_id);

	return ret;
}

int app_context_get_instance_id(app_context_h app_context, char **instance_id)
{
	if (app_context == NULL || app_context->instance_id == NULL || instance_id == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	*instance_id = strdup(app_context->instance_id);
	if (*instance_id == NULL)
		return app_manager_error(APP_MANAGER_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL); /* LCOV_EXCL_LINE */

	return APP_MANAGER_ERROR_NONE;
}

int app_context_get_app_context_by_pid(pid_t pid, app_context_h *app_context)
{
	int ret;
	retrieval_context_s retrieval_context = {
		.app_id = NULL,
		.pid = pid,
		.pkg_id = NULL,
		.app_state = APP_STATE_UNDEFINED,
		.is_sub_app = false,
		.matched = false,
		.instance_id = NULL
	};

	if (pid <= 0 || app_context == NULL)
		return app_manager_error(APP_MANAGER_ERROR_INVALID_PARAMETER, __FUNCTION__, NULL);

	aul_app_get_running_app_instance_info(app_context_retrieve_app_context, &retrieval_context);
	if (retrieval_context.matched == false)
		return app_manager_error(APP_MANAGER_ERROR_NO_SUCH_APP, __FUNCTION__, NULL);

	ret = app_context_create(retrieval_context.app_id,
			retrieval_context.pid,
			retrieval_context.pkg_id,
			retrieval_context.app_state,
			retrieval_context.is_sub_app,
			retrieval_context.instance_id,
			app_context);
	free((void *)retrieval_context.app_id);
	free(retrieval_context.pkg_id);

	return ret;
}

int app_context_unset_status_cb(app_manager_app_context_status_cb callback, const char *appid)
{
	struct status_listen_info *info;

	if (callback == NULL || appid == NULL)
		return APP_MANAGER_ERROR_INVALID_PARAMETER;

	info = __find_status_listen_info(callback, appid);
	if (info == NULL)
		return APP_MANAGER_ERROR_INVALID_PARAMETER;

	status_listen_list = g_list_remove(status_listen_list, info);
	aul_ignore_app_status(info->handle);
	__destroy_status_listen_info(info);

	return APP_MANAGER_ERROR_NONE;
}

static void __foreach_window_info_cb(aul_window_info_h info, void *data)
{
	GList **list = (GList **)data;
	int visibility;
	int pid;
	int ret;

	if (info == NULL || list == NULL) {
		LOGE("Invalid parameter");
		return;
	}

	ret = aul_window_info_get_visibility(info, &visibility);
	if (ret < 0) {
		LOGE("Failed to get window visibility");
		return;
	}

	if (visibility < 0 || visibility > 1)
		return;

	ret = aul_window_info_get_pid(info, &pid);
	if (ret < 0) {
		LOGE("Failed to get pid");
		return;
	}

	*list = g_list_append(*list, GINT_TO_POINTER(pid));
}

static int __foreach_app_context_cb(const aul_app_info *aul_app_context, void *data)
{
	GHashTable *app_context_table = (GHashTable *)data;
	app_context_h app_context;
	app_state_e app_state;
	int ret;

	if (aul_app_context == NULL || app_context_table == NULL) {
		LOGE("Invalid parameter");
		return -1;
	}

	app_state = app_context_get_app_status(aul_app_context->status);
	ret = app_context_create(aul_app_context->appid,
			aul_app_context->pid,
			aul_app_context->pkgid,
			app_state,
			(bool)aul_app_context->is_sub_app,
			aul_app_context->instance_id,
			&app_context);
	if (ret != APP_MANAGER_ERROR_NONE) {
		LOGE("Failed to create app context - %s(%d)",
				aul_app_context->appid, aul_app_context->pid);
		return -1;
	}

	g_hash_table_insert(app_context_table, GINT_TO_POINTER(aul_app_context->pid), app_context);

	return 0;
}

int app_context_foreach_visible_app_context(app_manager_app_context_cb callback, void *user_data)
{
	aul_window_stack_h handle = NULL;
	GHashTable *app_context_table;
	app_context_h app_context;
	GList *pid_list = NULL;
	GList *iter;
	int ret;

	if (callback == NULL)
		return APP_MANAGER_ERROR_INVALID_PARAMETER;

	app_context_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
			NULL, (GDestroyNotify)app_context_destroy);
	if (app_context_table == NULL)
		return APP_MANAGER_ERROR_OUT_OF_MEMORY; /* LCOV_EXCL_LINE */

	ret = aul_app_get_all_running_app_info(__foreach_app_context_cb, app_context_table);
	if (ret != AUL_R_OK) {
		/* LCOV_EXCL_START */
		g_hash_table_destroy(app_context_table);
		return APP_MANAGER_ERROR_IO_ERROR;
		/* LCOV_EXCL_STOP */
	}

	ret = aul_window_stack_get(&handle);
	if (ret < 0) {
		/* LCOV_EXCL_START */
		g_hash_table_destroy(app_context_table);
		return APP_MANAGER_ERROR_IO_ERROR;
		/* LCOV_EXCL_STOP */
	}

	ret = aul_window_stack_foreach(handle, __foreach_window_info_cb, &pid_list);
	if (ret < 0) {
		aul_window_stack_del(handle);
		g_hash_table_destroy(app_context_table);
		return APP_MANAGER_ERROR_IO_ERROR;
	}
	aul_window_stack_del(handle);

	iter = g_list_first(pid_list);
	while (iter) {
		app_context = (app_context_h)g_hash_table_lookup(app_context_table, iter->data);
		if (app_context) {
			if (!callback(app_context, user_data))
				break;
		}
		iter = g_list_next(iter);
	}
	g_list_free(pid_list);
	g_hash_table_destroy(app_context_table);

	return APP_MANAGER_ERROR_NONE;
}
