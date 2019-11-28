/*
 * Copyright (c) 2016 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <ctype.h>
#include <bundle_internal.h>
#include <dlog.h>
#include <aul.h>
#include <aul_sock.h>
#include <aul_screen_connector.h>

#include "amd.h"
#include "amd_app_group.h"
#include "amd_screen_connector.h"
#include "status.h"

#define SUSPEND_INTERVAL 5 /* sec */
#undef LOG_TAG
#define LOG_TAG "AMD_SCREEN_CONNECTOR"
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

struct app_screen_s {
	char *appid;
	char *instance_id;
	int pid;
	uid_t uid;
	unsigned int surf;
	int screen_type;
	int caller_pid;
	GList *viewer_list;
};

struct viewer_info_s {
	int pid;
	int screen_type;
	bool priv;
	unsigned int ref;
	aul_screen_status_e status;
	GList *watch_list;
};

struct user_info_s {
	uid_t uid;
	GList *screen_viewer_list;
	GList *app_screen_list;
};

static GHashTable *user_table;

static struct app_screen_s *__create_app_screen(int pid, uid_t uid,
		const char *appid, unsigned int surf, const char *instance_id,
		int screen_type, int caller_pid)
{
	struct app_screen_s *app_screen;

	app_screen = calloc(1, sizeof(struct app_screen_s));
	if (app_screen == NULL) {
		LOGE("out of memory");
		return NULL;
	}

	app_screen->appid = strdup(appid);
	if (app_screen->appid == NULL) {
		LOGE("out of memory");
		free(app_screen);
		return NULL;
	}

	app_screen->instance_id = strdup(instance_id);
	if (app_screen->instance_id == NULL) {
		LOGE("out of memory");
		free(app_screen->appid);
		free(app_screen);
		return NULL;
	}

	app_screen->pid = pid;
	app_screen->uid = uid;
	app_screen->surf = surf;
	app_screen->screen_type = screen_type;
	app_screen->caller_pid = caller_pid;

	return app_screen;
}

static void __destroy_app_screen(gpointer data)
{
	struct app_screen_s *app_screen = (struct app_screen_s *)data;
	struct viewer_info_s *viewer_info;
	GList *iter;

	if (app_screen == NULL)
		return;

	if (app_screen->viewer_list) {
		iter = app_screen->viewer_list;
		while (iter) {
			viewer_info = (struct viewer_info_s *)iter->data;
			viewer_info->watch_list = g_list_remove(
					viewer_info->watch_list, app_screen);
			iter = g_list_next(iter);
		}
		g_list_free(app_screen->viewer_list);
	}

	if (app_screen->instance_id)
		free(app_screen->instance_id);
	if (app_screen->appid)
		free(app_screen->appid);
	free(app_screen);
}

static gint __compare_instance_id(gconstpointer a, gconstpointer b)
{
	struct app_screen_s *app_screen = (struct app_screen_s *)a;
	const char *instance_id = (const char *)b;

	if (app_screen == NULL || instance_id == NULL)
		return -1;

	if (!strcmp(app_screen->instance_id, instance_id))
		return 0;

	return -1;
}

static void __destroy_viewer_info(struct viewer_info_s *viewer_info)
{
	struct app_screen_s *app_screen;
	GList *iter;

	if (viewer_info == NULL)
		return;

	if (viewer_info->watch_list) {
		iter = viewer_info->watch_list;
		while (iter) {
			app_screen = (struct app_screen_s *)iter->data;
			app_screen->viewer_list = g_list_remove(
					app_screen->viewer_list, viewer_info);
			iter = g_list_next(iter);
		}
		g_list_free(viewer_info->watch_list);
	}

	free(viewer_info);
}

static struct viewer_info_s *__create_viewer_info(int pid, int screen_type,
		bool priv, unsigned int ref)
{
	struct viewer_info_s *viewer_info;

	viewer_info = calloc(1, sizeof(struct viewer_info_s));
	if (viewer_info == NULL) {
		LOGE("out of memory");
		return NULL;
	}

	viewer_info->pid = pid;
	viewer_info->screen_type = screen_type;
	viewer_info->priv = priv;
	viewer_info->ref = ref;

	return viewer_info;
}

static void __destroy_user_info(gpointer data)
{
	struct user_info_s *user_info = (struct user_info_s *)data;

	if (user_info == NULL)
		return;

	if (user_info->app_screen_list) {
		g_list_free_full(user_info->app_screen_list,
				__destroy_app_screen);
	}
	if (user_info->screen_viewer_list)
		g_list_free_full(user_info->screen_viewer_list, free);
	free(user_info);
}

static struct user_info_s *__create_user_info(uid_t uid)
{
	struct user_info_s *user_info;

	user_info = malloc(sizeof(struct user_info_s));
	if (user_info == NULL) {
		LOGE("out of memory");
		return NULL;
	}

	user_info->uid = uid;
	user_info->screen_viewer_list = NULL;
	user_info->app_screen_list = NULL;

	return user_info;
}

static bundle *__create_bundle(struct app_screen_s *app_screen,
		const char *event)
{
	bundle *b;

	b = bundle_create();
	if (b == NULL) {
		LOGE("out of memory");
		return NULL;
	}

	bundle_add_str(b, "__AUL_SC_EVENT__", event);
	bundle_add_str(b, "__AUL_SC_APPID__", app_screen->appid);
	bundle_add_byte(b, "__AUL_SC_PID__", &app_screen->pid, sizeof(int));
	bundle_add_byte(b, "__AUL_SC_SURFACE__",
			&app_screen->surf, sizeof(unsigned int));
	bundle_add_str(b, "__AUL_SC_INSTANCE_ID__", app_screen->instance_id);

	return b;
}

static void __send_app_screen_event(struct viewer_info_s *viewer_info,
		struct app_screen_s *app_screen, const char *event)
{
	bundle *b;
	char endpoint[128];

	b = __create_bundle(app_screen, event);
	if (b == NULL) {
		LOGE("out of memory");
		return;
	}

	snprintf(endpoint, sizeof(endpoint), "app_screen_event:%u:%d",
			viewer_info->ref, viewer_info->pid);
	amd_app_com_send(endpoint, app_screen->pid, b, app_screen->uid);
	bundle_free(b);
}

static void __send_app_screen_added(gpointer data, gpointer user_data)
{
	struct viewer_info_s *viewer_info = (struct viewer_info_s *)data;
	struct app_screen_s *app_screen = (struct app_screen_s *)user_data;

	if (viewer_info->pid == app_screen->pid)
		return;
	if (viewer_info->priv && viewer_info->pid != app_screen->caller_pid)
		return;
	if (!(viewer_info->screen_type & app_screen->screen_type))
		return;
	__send_app_screen_event(viewer_info, app_screen, "add_screen");
}

static void __send_app_screen_removed(gpointer data, gpointer user_data)
{
	struct viewer_info_s *viewer_info = (struct viewer_info_s *)data;
	struct app_screen_s *app_screen = (struct app_screen_s *)user_data;

	if (viewer_info->pid == app_screen->pid)
		return;
	if (viewer_info->priv && viewer_info->pid != app_screen->caller_pid)
		return;
	if (!(viewer_info->screen_type & app_screen->screen_type))
		return;
	__send_app_screen_event(viewer_info, app_screen, "remove_screen");
}

static void __send_app_screen_updated(gpointer data, gpointer user_data)
{
	struct viewer_info_s *viewer_info = (struct viewer_info_s *)data;
	struct app_screen_s *app_screen = (struct app_screen_s *)user_data;

	if (viewer_info->pid == app_screen->pid)
		return;
	if (viewer_info->priv && viewer_info->pid != app_screen->caller_pid)
		return;
	if (!(viewer_info->screen_type & app_screen->screen_type))
		return;
	__send_app_screen_event(viewer_info, app_screen, "update_screen");
}

static gint __compare_app_screen_instance_id(gconstpointer a, gconstpointer b)
{
	struct app_screen_s *app_screen = (struct app_screen_s *)a;
	const char *instance_id = (const char *)b;

	if (strcmp(app_screen->instance_id, instance_id) == 0)
		return 0;

	return -1;
}

static unsigned int __screen_connector_get_surface_id(const char *instance_id,
		uid_t uid)
{
	struct user_info_s *user_info;
	struct app_screen_s *app_screen;
	GList *found;

	if (instance_id == NULL)
		return 0;

	user_info = g_hash_table_lookup(user_table, GUINT_TO_POINTER(uid));
	if (user_info == NULL)
		return 0;

	found = g_list_find_custom(user_info->app_screen_list,
			instance_id, __compare_app_screen_instance_id);
	if (found) {
		app_screen = (struct app_screen_s *)found->data;
		return app_screen->surf;
	}

	return 0;
}

static int __get_screen_type(int app_type)
{
	switch (app_type) {
	case AMD_AT_UI_APP:
		return AUL_SCREEN_TYPE_UI;
	case AMD_AT_WIDGET_APP:
		return AUL_SCREEN_TYPE_WIDGET;
	case AMD_AT_WATCH_APP:
		return AUL_SCREEN_TYPE_WATCH;
	default:
		return -1;
	}
}

static int __get_pid_by_surf(int pid, unsigned int surf)
{
	int *pids = NULL;
	int cnt = 0;
	int i;
	unsigned int wid;
	app_group_h h;

	_app_group_get_group_pids(pid, &cnt, &pids);
	for (i = 0; i < cnt; ++i) {
		h = _app_group_find(pids[i]);
		wid = (unsigned int)_app_group_get_window(h);
		if (wid == surf) {
			LOGD("pid(%d), surf(%u)", pids[i], surf);
			pid = pids[i];
		}
	}
	free(pids);

	return pid;
}

static gboolean __suspend_timer(gpointer data)
{
	int pid = GPOINTER_TO_INT(data);
	int ret;

	if (pid < 1)
		return FALSE;

	ret = amd_suspend_update_status(pid, AMD_SUSPEND_STATUS_INCLUDE);
	LOGD("pid(%d), result(%d)", pid, ret);

	return FALSE;
}

static gint __compare_app_screen_surf(gconstpointer a, gconstpointer b)
{
	struct app_screen_s *app_screen = (struct app_screen_s *)a;
	unsigned int surf = GPOINTER_TO_UINT(b);

	if (app_screen->surf == surf)
		return 0;

	return -1;
}

static const char *__screen_connector_get_appid_by_surface_id(unsigned int surf,
		uid_t uid)
{
	struct user_info_s *user_info;
	struct app_screen_s *app_screen;
	GList *found;

	user_info = g_hash_table_lookup(user_table, GUINT_TO_POINTER(uid));
	if (user_info == NULL)
		return NULL;

	found = g_list_find_custom(user_info->app_screen_list,
			GUINT_TO_POINTER(surf), __compare_app_screen_surf);
	if (found) {
		app_screen = (struct app_screen_s *)found->data;
		return app_screen->appid;
	}

	return NULL;
}

static const char *__screen_connector_get_instance_id_by_surface_id(
		unsigned int surf, uid_t uid)
{
	struct user_info_s *user_info;
	struct app_screen_s *app_screen;
	GList *found;

	user_info = g_hash_table_lookup(user_table, GUINT_TO_POINTER(uid));
	if (user_info == NULL)
		return NULL;

	found = g_list_find_custom(user_info->app_screen_list,
			GUINT_TO_POINTER(surf), __compare_app_screen_surf);
	if (found) {
		app_screen = (struct app_screen_s *)found->data;
		return app_screen->instance_id;
	}

	return NULL;
}

/* TODO: The provider_appid should be provider_instance_id. */
static int __send_viewer_visibility_to_provider(const char *provider_appid,
		aul_screen_status_e status, int viewer_pid, uid_t viewer_uid)
{
	bundle *b;

	b = bundle_create();
	if (b == NULL) {
		LOGE("out of memory");
		return -1;
	}

	bundle_add_byte(b, "__AUL_SC_VIEWER_STATUS__",
			&status, sizeof(aul_screen_status_e));
	amd_app_com_send(provider_appid, viewer_pid, b, viewer_uid);
	bundle_free(b);
	LOGD("send viewer status to %s(%d)", provider_appid, status);

	return 0;
}

static gint __compare_viewer_pid(gconstpointer a, gconstpointer b)
{
	struct viewer_info_s *viewer_info = (struct viewer_info_s *)a;
	int pid = GPOINTER_TO_INT(b);

	if (viewer_info->pid == pid)
		return 0;

	return -1;
}

static int __screen_connector_update_screen_viewer_status(int pid, int status,
		unsigned int surf, uid_t uid)
{
	struct user_info_s *user_info;
	struct app_screen_s *app_screen;
	struct viewer_info_s *viewer_info;
	bool send_pause = true;
	GList *found;
	GList *iter;

	user_info = g_hash_table_lookup(user_table, GUINT_TO_POINTER(uid));
	if (user_info == NULL)
		return -1;

	found = g_list_find_custom(user_info->screen_viewer_list,
			GINT_TO_POINTER(pid), __compare_viewer_pid);
	if (found == NULL)
		return -1;

	viewer_info = (struct viewer_info_s *)found->data;
	viewer_info->status = status;

	found = g_list_find_custom(user_info->app_screen_list,
			GUINT_TO_POINTER(surf), __compare_app_screen_surf);
	if (found == NULL)
		return -1;

	app_screen = (struct app_screen_s *)found->data;
	found = g_list_find(app_screen->viewer_list, viewer_info);
	if (!found) {
		app_screen->viewer_list = g_list_append(app_screen->viewer_list,
				viewer_info);
	}

	found = g_list_find(viewer_info->watch_list, app_screen);
	if (!found) {
		viewer_info->watch_list = g_list_append(viewer_info->watch_list,
				app_screen);
	}

	if (status == AUL_SCREEN_STATUS_PAUSE) {
		iter = app_screen->viewer_list;
		while (iter) {
			viewer_info = (struct viewer_info_s *)iter->data;
			if (viewer_info->status != AUL_SCREEN_STATUS_PAUSE) {
				/*
				 * Every veiwer must be paused to send
				 * viewer pause event to provider
				 */
				send_pause = false;
				break;
			}
			iter = g_list_next(iter);
		}
		if (send_pause) {
			__send_viewer_visibility_to_provider(app_screen->appid,
					status, pid, uid);
		}
	} else if (status == AUL_SCREEN_STATUS_RESUME ||
			status == AUL_SCREEN_STATUS_PRE_RESUME) {
		__send_viewer_visibility_to_provider(app_screen->appid, status,
				pid, uid);
	} else {
		LOGW("Unknown status(%d)", status);
	}

	return 0;
}

static int __screen_connector_send_update_request(const char *appid,
		const char *instance_id, uid_t uid)
{
	amd_app_status_h app_status;
	struct user_info_s *user_info;
	struct app_screen_s *app_screen;
	int dummy = 0;
	int pid;
	int ret;
	GList *found;

	user_info = g_hash_table_lookup(user_table, GUINT_TO_POINTER(uid));
	if (user_info == NULL)
		return -1;

	if (instance_id) {
		app_status = amd_app_status_find_by_instance_id(appid,
				instance_id, uid);
	} else {
		app_status = amd_app_status_find_by_appid(appid, uid);
	}
	if (app_status == NULL)
		return -1;
	if (amd_app_status_get_status(app_status) == STATUS_DYING)
		return -1;
	if (amd_app_status_get_app_type(app_status) != AMD_AT_UI_APP)
		return -1;
	if (amd_app_status_is_home_app(app_status))
		return -1;
	if (instance_id == NULL) {
		instance_id = amd_app_status_get_instance_id(app_status);
		if (instance_id == NULL)
			return -1;
	}

	found = g_list_find_custom(user_info->app_screen_list, instance_id,
			__compare_instance_id);
	if (found == NULL)
		return -1;

	app_screen = (struct app_screen_s *)found->data;
	pid = __get_pid_by_surf(app_screen->pid, app_screen->surf);
	ret = amd_suspend_update_status(pid, AMD_SUSPEND_STATUS_EXCLUDE);
	if (ret < 0)
		return -1;

	ret = aul_sock_send_raw(pid, uid, APP_UPDATE_REQUESTED,
			(unsigned char *)&dummy, 0, AUL_SOCK_NOREPLY);
	if (ret < 0) {
		LOGE("Failed to send the update request");
		amd_suspend_update_status(pid, AMD_SUSPEND_STATUS_INCLUDE);
		return -1;
	}
	g_timeout_add_seconds(SUSPEND_INTERVAL, __suspend_timer,
			GINT_TO_POINTER(pid));
	LOGD("pid(%d), uid(%d)", pid, uid);

	return 0;
}

int _screen_connector_add_app_screen(int pid, unsigned int surf,
		const char *instance_id, uid_t uid)
{
	amd_app_status_h app_status;
	const char *appid;
	struct user_info_s *user_info;
	struct app_screen_s *app_screen;
	int caller_pid;
	int leader_pid;
	int app_type;
	int screen_type;
	int effective_pid;
	GList *found;

	user_info = g_hash_table_lookup(user_table, GUINT_TO_POINTER(uid));
	if (user_info == NULL)
		return -1;

	effective_pid = _status_get_effective_pid(pid);
	if (effective_pid < 0)
		return -1;

	leader_pid = _app_group_get_leader_pid(_app_group_find(effective_pid));
	if (leader_pid > 0)
		pid = leader_pid;
	else
		pid = effective_pid;

	app_status = amd_app_status_find_by_pid(pid);
	if (app_status == NULL) {
		LOGW("Failed to find app status info - pid(%d), uid(%d)",
				pid, uid);
		return -1;
	}

	if (amd_app_status_is_home_app(app_status))
		return 0;

	appid = amd_app_status_get_appid(app_status);
	if (instance_id == NULL)
		instance_id = amd_app_status_get_instance_id(app_status);

	found = g_list_find_custom(user_info->app_screen_list, instance_id,
			__compare_instance_id);
	if (found) {
		app_screen = (struct app_screen_s *)found->data;
		if (app_screen->surf == surf) {
			LOGD("Already exists");
			return 0;
		}

		app_screen->surf = surf;
		g_list_foreach(user_info->screen_viewer_list,
				__send_app_screen_updated, app_screen);
		LOGW("surf is changed to %u", surf);
		return 0;
	}

	caller_pid = amd_app_status_get_first_caller_pid(app_status);
	app_type = amd_app_status_get_app_type(app_status);
	screen_type = __get_screen_type(app_type);
	app_screen = __create_app_screen(pid, uid, appid, surf, instance_id,
			screen_type, caller_pid);
	if (app_screen == NULL)
		return -1;

	user_info->app_screen_list = g_list_append(user_info->app_screen_list,
			app_screen);
	g_list_foreach(user_info->screen_viewer_list,
			__send_app_screen_added, app_screen);
	LOGD("pid(%d), appid(%s), surf(%d), uid(%d)", pid, appid, surf, uid);

	return 0;
}

static int __screen_connector_remove_app_screen(int pid,
		const char *instance_id, uid_t uid)
{
	struct user_info_s *user_info;
	struct app_screen_s *app_screen;
	amd_app_status_h app_status;
	int leader_pid;
	int effective_pid;
	GList *found;

	user_info = g_hash_table_lookup(user_table, GUINT_TO_POINTER(uid));
	if (user_info == NULL)
		return -1;

	effective_pid = _status_get_effective_pid(pid);
	if (effective_pid < 0)
		return -1;

	leader_pid = _app_group_get_leader_pid(_app_group_find(effective_pid));
	if (leader_pid > 0)
		pid = leader_pid;
	else
		pid = effective_pid;

	app_status = amd_app_status_find_by_pid(pid);
	if (app_status == NULL) {
		LOGW("Failed to find app status info - pid(%d), uid(%d)",
				pid, uid);
		return -1;
	}

	if (amd_app_status_is_home_app(app_status))
		return 0;

	if (instance_id == NULL)
		instance_id = amd_app_status_get_instance_id(app_status);

	found = g_list_find_custom(user_info->app_screen_list, instance_id,
			__compare_instance_id);
	if (found == NULL)
		return -1;

	app_screen = (struct app_screen_s *)found->data;
	g_list_foreach(user_info->screen_viewer_list,
			__send_app_screen_removed, app_screen);
	user_info->app_screen_list = g_list_remove(user_info->app_screen_list,
			app_screen);
	__destroy_app_screen(app_screen);
	LOGD("pid(%d), instance_id(%s)", pid, instance_id);

	return 0;
}

static gint __compare_viewers(gconstpointer a, gconstpointer b)
{
	struct viewer_info_s *viewer_a = (struct viewer_info_s *)a;
	struct viewer_info_s *viewer_b = (struct viewer_info_s *)b;

	if (viewer_a->pid == viewer_b->pid &&
			viewer_a->screen_type == viewer_b->screen_type &&
			viewer_a->priv == viewer_b->priv &&
			viewer_a->ref == viewer_b->ref)
		return 0;

	return -1;
}

static int __screen_connector_update_app_screen(int pid, unsigned int surf,
		uid_t uid)
{
	amd_app_status_h app_status;
	struct user_info_s *user_info;
	struct app_screen_s *app_screen;
	const char *appid;
	const char *instance_id;
	int leader_pid;
	int effective_pid;
	GList *found;

	user_info = g_hash_table_lookup(user_table, GUINT_TO_POINTER(uid));
	if (user_info == NULL)
		return -1;

	effective_pid = _status_get_effective_pid(pid);
	if (effective_pid < 0)
		return -1;

	leader_pid = _app_group_get_leader_pid(_app_group_find(effective_pid));
	if (leader_pid > 0)
		pid = leader_pid;
	else
		pid = effective_pid;

	app_status = amd_app_status_find_by_pid(pid);
	if (app_status == NULL) {
		LOGW("Failed to find app status info - pid(%d), uid(%d)",
				pid, uid);
		return -1;
	}

	if (amd_app_status_is_home_app(app_status))
		return 0;

	appid = amd_app_status_get_appid(app_status);
	instance_id = amd_app_status_get_instance_id(app_status);

	found = g_list_find_custom(user_info->app_screen_list, instance_id,
			__compare_instance_id);
	if (found == NULL)
		return -1;

	app_screen = (struct app_screen_s *)found->data;
	if (app_screen->surf == surf)
		return 0;

	app_screen->surf = surf;
	g_list_foreach(user_info->screen_viewer_list,
			__send_app_screen_updated, app_screen);
	LOGD("pid(%d), appid(%s), surf(%d), uid(%d)", pid, appid, surf, uid);

	return 0;
}

static int __screen_connector_remove_app_screen_v2(int pid, uid_t uid)
{
	struct user_info_s *user_info;
	struct app_screen_s *app_screen;
	GList *iter;

	user_info = g_hash_table_lookup(user_table, GUINT_TO_POINTER(uid));
	if (user_info == NULL)
		return -1;

	iter = g_list_first(user_info->app_screen_list);
	while (iter) {
		app_screen = (struct app_screen_s *)iter->data;
		iter = g_list_next(iter);
		if (app_screen && app_screen->pid == pid) {
			LOGD("pid(%d), surf(%d)", pid, app_screen->surf);
			g_list_foreach(user_info->screen_viewer_list,
					__send_app_screen_removed, app_screen);
			user_info->app_screen_list = g_list_remove(
					user_info->app_screen_list,
					app_screen);
			__destroy_app_screen(app_screen);
		}
	}

	return 0;
}

static void __foreach_app_screen_list(gpointer data, gpointer user_data)
{
	__send_app_screen_added(user_data, data);
}

static int __screen_connector_add_screen_viewer(int pid, int screen_type,
		bool priv, unsigned int ref, uid_t uid)
{
	struct user_info_s *user_info;
	struct viewer_info_s *viewer_info;
	GList *list;

	pid = _status_get_effective_pid(pid);
	if (pid < 0)
		return -1;

	user_info = g_hash_table_lookup(user_table, GUINT_TO_POINTER(uid));
	if (user_info == NULL) {
		LOGW("user info is empty");
		return -1;
	}

	viewer_info = __create_viewer_info(pid, screen_type, priv, ref);
	if (viewer_info == NULL)
		return -1;

	list = g_list_find_custom(user_info->screen_viewer_list, viewer_info,
			__compare_viewers);
	if (list) {
		LOGD("Already exists");
		__destroy_viewer_info(viewer_info);
		return 0;
	}

	user_info->screen_viewer_list = g_list_append(
			user_info->screen_viewer_list, viewer_info);

	g_list_foreach(user_info->app_screen_list,
			__foreach_app_screen_list, viewer_info);
	LOGD("pid(%d), screen_type(%d), private(%d), ref(%u), uid(%d)",
			pid, screen_type, priv, ref, uid);

	return 0;
}

static int __screen_connector_remove_screen_viewer(int pid, int screen_type,
		bool priv, unsigned int ref, uid_t uid)
{
	struct user_info_s *user_info;
	struct viewer_info_s *viewer_info;
	GList *iter;

	user_info = g_hash_table_lookup(user_table, GUINT_TO_POINTER(uid));
	if (user_info == NULL) {
		LOGW("user info is empty");
		return -1;
	}

	pid = _status_get_effective_pid(pid);
	if (pid < 0)
		return -1;

	iter = g_list_first(user_info->screen_viewer_list);
	while (iter) {
		viewer_info = (struct viewer_info_s *)iter->data;
		iter = g_list_next(iter);
		if (viewer_info->pid == pid &&
				viewer_info->screen_type == screen_type &&
				viewer_info->priv == priv &&
				viewer_info->ref == ref) {
			user_info->screen_viewer_list = g_list_remove(
					user_info->screen_viewer_list,
					viewer_info);
			__destroy_viewer_info(viewer_info);
		}
	}

	LOGD("pid(%d), screen_type(%d), private(%d), ref(%u) uid(%d)",
			pid, screen_type, priv, ref, uid);

	return 0;
}

static int __screen_connector_remove_screen_viewer_v2(int pid, uid_t uid)
{
	struct user_info_s *user_info;
	struct viewer_info_s *viewer_info;
	GList *iter;

	user_info = g_hash_table_lookup(user_table, GUINT_TO_POINTER(uid));
	if (user_info == NULL) {
		LOGW("user info is empty");
		return -1;
	}

	iter = g_list_first(user_info->screen_viewer_list);
	while (iter) {
		viewer_info = (struct viewer_info_s *)iter->data;
		iter = g_list_next(iter);
		if (viewer_info->pid == pid) {
			user_info->screen_viewer_list = g_list_remove(
					user_info->screen_viewer_list,
					viewer_info);
			__destroy_viewer_info(viewer_info);
		}
	}

	return 0;
}

static int __screen_connector_usr_init(uid_t uid)
{
	struct user_info_s *user_info;

	user_info = g_hash_table_lookup(user_table, GUINT_TO_POINTER(uid));
	if (user_info) {
		LOGE("Already exists");
		return 0;
	}

	user_info = __create_user_info(uid);
	if (user_info == NULL)
		return -1;

	g_hash_table_insert(user_table, GUINT_TO_POINTER(uid), user_info);

	return 0;
}

static void __screen_connector_usr_fini(uid_t uid)
{
	g_hash_table_remove(user_table, GUINT_TO_POINTER(uid));
}

static int __dispatch_add_app_screen(amd_request_h req)
{
	uid_t uid = amd_request_get_target_uid(req);
	int pid = amd_request_get_pid(req);
	bundle *b = amd_request_get_bundle(req);
	const char *instance_id;
	const char *value;
	unsigned int surf;
	int ret;

	if (b == NULL)
		return -1;

	instance_id = bundle_get_val(b, AUL_K_INSTANCE_ID);
	value = bundle_get_val(b, AUL_K_WID);
	if (value == NULL)
		return -1;

	surf = atol(value);
	ret = _screen_connector_add_app_screen(pid, surf,
			instance_id, uid);
	LOGD("pid(%d), surf(%d), instance_id(%s), result(%d)",
			pid, surf, instance_id, ret);

	return 0;
}

static int __dispatch_remove_app_screen(amd_request_h req)
{
	uid_t uid = amd_request_get_target_uid(req);
	int pid = amd_request_get_pid(req);
	bundle *b = amd_request_get_bundle(req);
	const char *instance_id;
	int ret;

	if (b == NULL)
		return -1;

	instance_id = bundle_get_val(b, AUL_K_INSTANCE_ID);
	ret = __screen_connector_remove_app_screen(pid,
			instance_id, uid);
	LOGD("pid(%d), instance_id(%s), result(%d)",
			pid, instance_id, ret);

	return 0;
}

static int __dispatch_app_update_requested(amd_request_h req)
{
	uid_t uid = amd_request_get_target_uid(req);
	int caller_pid = amd_request_get_pid(req);
	bundle *b = amd_request_get_bundle(req);
	const char *appid;
	const char *instance_id;
	int ret;

	if (b == NULL)
		return -1;

	appid = bundle_get_val(b, AUL_K_APPID);
	if (appid == NULL)
		return -1;

	instance_id = bundle_get_val(b, AUL_K_INSTANCE_ID);
	ret = __screen_connector_send_update_request(appid, instance_id, uid);
	LOGD("appid(%s), instance_id(%s), caller_pid(%d), result(%d)",
			appid, instance_id, caller_pid, ret);

	return 0;
}

static int __dispatch_add_screen_viewer(amd_request_h req)
{
	uid_t uid = amd_request_get_target_uid(req);
	int pid = amd_request_get_pid(req);
	bundle *b = amd_request_get_bundle(req);
	const char *value;
	bool priv;
	int screen_type;
	unsigned int ref;
	int ret;

	if (b == NULL)
		return -1;

	value = bundle_get_val(b, AUL_K_SCREEN_TYPE);
	if (value == NULL)
		return -1;
	screen_type = atoi(value);

	value = bundle_get_val(b, AUL_K_VIEWER_REF);
	if (value == NULL)
		return -1;
	ref = atol(value);

	value = bundle_get_val(b, AUL_K_PRIVATE);
	if (value && strcmp(value, "true") == 0)
		priv = true;
	else
		priv = false;

	ret = __screen_connector_add_screen_viewer(pid, screen_type,
			priv, ref, uid);
	LOGD("pid(%d), screen_type(%d), private(%d), result(%d)",
			pid, screen_type, priv, ret);

	return 0;
}

static int __dispatch_remove_screen_viewer(amd_request_h req)
{
	uid_t uid = amd_request_get_target_uid(req);
	int pid = amd_request_get_pid(req);
	bundle *b = amd_request_get_bundle(req);
	const char *value;
	bool priv;
	int screen_type;
	unsigned int ref;
	int ret;

	if (b == NULL)
		return -1;

	value = bundle_get_val(b, AUL_K_SCREEN_TYPE);
	if (value == NULL)
		return -1;
	screen_type = atoi(value);

	value = bundle_get_val(b, AUL_K_VIEWER_REF);
	if (value == NULL)
		return -1;
	ref = atol(value);

	value = bundle_get_val(b, AUL_K_PRIVATE);
	if (value && strcmp(value, "true") == 0)
		priv = true;
	else
		priv = false;

	ret = __screen_connector_remove_screen_viewer(pid, screen_type,
			priv, ref, uid);
	LOGD("pid(%d), screen_type(%d), private(%d), result(%d)",
			pid, screen_type, priv, ret);

	return 0;
}

static int __screen_connector_checker(amd_cynara_caller_info_h info,
		amd_request_h req, void *data)
{
	bundle *b = amd_request_get_bundle(req);
	const char *type_str;
	int type;

	if (b == NULL)
		return -1;

	type_str = bundle_get_val(b, AUL_K_SCREEN_TYPE);
	if (type_str == NULL)
		return -1;

	type = atoi(type_str);
	if (type & AUL_SCREEN_TYPE_UI)
		return amd_cynara_simple_checker(info, req, PRIVILEGE_PLATFORM);

	return amd_cynara_simple_checker(info, req, PRIVILEGE_WIDGET_VIEWER);
}

static int __dispatch_app_get_appid_by_surface_id(amd_request_h req)
{
	uid_t uid = amd_request_get_target_uid(req);
	bundle *b = amd_request_get_bundle(req);
	unsigned int *surf = NULL;
	const char *appid;
	size_t size;
	bundle *ret_b;

	if (b == NULL) {
		amd_request_send_result(req, -1);
		return -1;
	}

	bundle_get_byte(b, "__AUL_SC_SURFACE__", (void **)&surf, &size);
	if (surf == NULL) {
		LOGE("Failed to get surface");
		amd_request_send_result(req, -1);
		return -1;
	}

	appid = __screen_connector_get_appid_by_surface_id(*surf, uid);
	if (appid == NULL) {
		LOGE("Failed to get appid");
		amd_request_send_result(req, -1);
		return -1;
	}

	ret_b = bundle_create();
	if (ret_b == NULL) {
		LOGE("Out of memory");
		amd_request_send_result(req, -1);
		return -1;
	}

	bundle_add_str(ret_b, AUL_K_APPID, appid);
	aul_sock_send_bundle_with_fd(amd_request_remove_fd(req),
			amd_request_get_cmd(req), ret_b, AUL_SOCK_NOREPLY);
	bundle_free(ret_b);

	return 0;
}

static int __dispatch_app_get_instance_id_by_surface_id(amd_request_h req)
{
	uid_t uid = amd_request_get_target_uid(req);
	bundle *b = amd_request_get_bundle(req);
	unsigned int *surf = NULL;
	const char *instance_id;
	size_t size;
	bundle *ret_b;

	if (b == NULL) {
		amd_request_send_result(req, -1);
		return -1;
	}

	bundle_get_byte(b, "__AUL_SC_SURFACE__", (void **)&surf, &size);
	if (surf == NULL) {
		LOGE("Failed to get surface");
		amd_request_send_result(req, -1);
		return -1;
	}

	instance_id = __screen_connector_get_instance_id_by_surface_id(*surf,
			uid);
	if (instance_id == NULL) {
		LOGE("Failed to get instance_id");
		amd_request_send_result(req, -1);
		return -1;
	}

	ret_b = bundle_create();
	if (ret_b == NULL) {
		LOGE("Out of memory");
		amd_request_send_result(req, -1);
		return -1;
	}

	bundle_add_str(ret_b, AUL_K_INSTANCE_ID, instance_id);
	aul_sock_send_bundle_with_fd(amd_request_remove_fd(req),
			amd_request_get_cmd(req), ret_b, AUL_SOCK_NOREPLY);
	bundle_free(ret_b);

	return 0;
}

static int __dispatch_update_screen_viewer_status(amd_request_h req)
{
	uid_t uid = amd_request_get_target_uid(req);
	int pid = amd_request_get_pid(req);
	bundle *b = amd_request_get_bundle(req);
	const char *val;
	aul_screen_status_e status;
	unsigned int surf;
	int r;

	if (b == NULL) {
		amd_request_send_result(req, -1);
		return -1;
	}

	val = bundle_get_val(b, "__AUL_SC_VIEWER_STATUS__");
	if (val == NULL || !isdigit(*val)) {
		LOGE("Failed to get viewer status");
		amd_request_send_result(req, -1);
		return -1;
	}

	status = atoi(val);

	val = bundle_get_val(b, AUL_K_WID);
	if (val == NULL || !isdigit(*val)) {
		LOGE("Failed to get surface id");
		amd_request_send_result(req, -1);
		return -1;
	}

	surf = strtoul(val, NULL, 10);

	r = __screen_connector_update_screen_viewer_status(pid, status,
			surf, uid);
	amd_request_send_result(req, r);

	return 0;
}

static amd_request_cmd_dispatch __dispatch_table[] = {
	{
		.cmd = ADD_APP_SCREEN,
		.callback = __dispatch_add_app_screen
	},
	{
		.cmd = REMOVE_APP_SCREEN,
		.callback = __dispatch_remove_app_screen
	},
	{
		.cmd = APP_UPDATE_REQUESTED,
		.callback = __dispatch_app_update_requested
	},
	{
		.cmd = ADD_SCREEN_VIEWER,
		.callback = __dispatch_add_screen_viewer
	},
	{
		.cmd = REMOVE_SCREEN_VIEWER,
		.callback = __dispatch_remove_screen_viewer
	},
	{
		.cmd = APP_GET_APPID_BY_SURFACE_ID,
		.callback = __dispatch_app_get_appid_by_surface_id
	},
	{
		.cmd = APP_GET_INSTANCE_ID_BY_SURFACE_ID,
		.callback = __dispatch_app_get_instance_id_by_surface_id
	},
	{
		.cmd = UPDATE_SCREEN_VIEWER_STATUS,
		.callback = __dispatch_update_screen_viewer_status
	},
};

static amd_cynara_checker __cynara_checkers[] = {
	{
		.cmd = ADD_SCREEN_VIEWER,
		.checker = __screen_connector_checker,
		.data = NULL
	},
	{
		.cmd = REMOVE_SCREEN_VIEWER,
		.checker = __screen_connector_checker,
		.data = NULL
	},
	{
		.cmd = APP_UPDATE_REQUESTED,
		.checker = amd_cynara_simple_checker,
		.data = PRIVILEGE_PLATFORM
	},
};

static int __on_launch_status(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int pid = arg1;
	uid_t uid = arg2;
	app_group_h app_group = _app_group_find(pid);
	unsigned int surf = (unsigned int)_app_group_get_window(app_group);

	__screen_connector_update_app_screen(pid, surf, uid);
	amd_noti_send("screen_connector.app_screen.update", pid, (int)surf,
			NULL, NULL);
	return 0;
}

static int __on_app_status_end(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	amd_app_status_h h = arg3;

	if (amd_app_status_get_status(h) == STATUS_DYING) {
		__screen_connector_remove_app_screen_v2(
				amd_app_status_get_pid(h),
				amd_app_status_get_uid(h));
	}

	return 0;
}

static int __on_app_status_cleanup(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int pid = arg1;
	uid_t uid = arg2;

	__screen_connector_remove_app_screen_v2(pid, uid);
	__screen_connector_remove_screen_viewer_v2(pid, uid);

	return 0;
}

static int __on_login(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	uid_t uid = arg1;
	int status = arg2;

	if (status & (AMD_UID_STATE_OPENING | AMD_UID_STATE_ONLINE |
			AMD_UID_STATE_ACTIVE))
		__screen_connector_usr_init(uid);

	return 0;
}

static int __on_logout(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	uid_t uid = arg1;
	int status = arg2;

	if (status & (AMD_UID_STATE_CLOSING | AMD_UID_STATE_OFFLINE))
		__screen_connector_usr_fini(uid);

	return 0;
}

static int __on_widget_app_restart(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int pid = arg1;
	uid_t uid = (uid_t)arg2;

	__screen_connector_remove_app_screen_v2(pid, uid);

	return 0;
}

static int __on_widget_running_info(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	unsigned int *surf = GINT_TO_POINTER(arg1);
	uid_t uid = (uid_t)arg2;
	const char *instance_id = (const char *)arg3;

	*surf = __screen_connector_get_surface_id(instance_id, uid);

	return 0;
}

int _screen_connector_init(void)
{
	int r;

	LOGD("screen connector init");

	user_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
			NULL, __destroy_user_info);
	if (user_table == NULL) {
		LOGE("Failed to create user table");
		return -1;
	}

	r = amd_request_register_cmds(__dispatch_table,
			ARRAY_SIZE(__dispatch_table));
	if (r < 0) {
		LOGE("Failed to register cmds");
		return -1;
	}

	r = amd_cynara_register_checkers(__cynara_checkers,
			ARRAY_SIZE(__cynara_checkers));
	if (r < 0) {
		LOGE("Failed to register checkers");
		return -1;
	}

	amd_noti_listen("launch.status.fg", __on_launch_status);
	amd_noti_listen("launch.status.focus", __on_launch_status);
	amd_noti_listen("app_status.update_status.end", __on_app_status_end);
	amd_noti_listen("app_status.cleanup", __on_app_status_cleanup);
	amd_noti_listen("login_monitor.login", __on_login);
	amd_noti_listen("login_monitor.logout", __on_logout);
	amd_noti_listen("widget.on_app_dead.restart", __on_widget_app_restart);
	amd_noti_listen("widget.running_info.send", __on_widget_running_info);

	return 0;
}

void _screen_connector_fini(void)
{
	LOGD("screen connector fini");

	if (user_table)
		g_hash_table_destroy(user_table);
}
