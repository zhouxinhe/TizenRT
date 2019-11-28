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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <glib.h>
#include <dlog.h>
#include <aul.h>
#include <aul_svc.h>
#include <bundle_internal.h>
#include <aul_sock.h>
#include <wayland-client.h>
#include <wayland-tbm-client.h>
#include <tizen-extension-client-protocol.h>
#include <system_info.h>

#include "amd.h"
#include "amd_app_group.h"
#include "amd_screen_connector.h"
#include "status.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "AMD_APP_GROUP"

#define APP_SVC_K_LAUNCH_MODE   "__APP_SVC_LAUNCH_MODE__"
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define STATUS_FOREGROUND "fg"
#define STATUS_BACKGROUND "bg"
#define TIZEN_FEATURE_TERMINATE_UNMANAGEABLE_APP \
	(!(amd_config_get_tizen_profile() & (AMD_TIZEN_PROFILE_TV)))

typedef enum {
	APP_GROUP_LAUNCH_MODE_SINGLE = 0,
	APP_GROUP_LAUNCH_MODE_GROUP,
	APP_GROUP_LAUNCH_MODE_CALLER,
} app_group_launch_mode;

typedef struct _app_group_context_t {
	int pid;
	int wid;
	int status;
	int caller_pid;
	app_group_launch_mode launch_mode;
	bool fg;
	bool group_sig;
	bool can_be_leader;
	bool reroute;
	bool can_shift;
	bool recycle;
} app_group_context_t;

struct launch_context_s {
	app_group_launch_mode mode;
	bool can_attach;
	int lpid;
};

static struct wl_display *display;
static struct tizen_policy *tz_policy;
static int tz_policy_initialized;
static uint32_t tz_policy_id;
static GHashTable *app_group_hash;
static GList *recycle_bin;
static struct launch_context_s __launch_context;

static int __app_group_set_status(app_group_h h, int status, bool force);
static void __app_group_clear_top(app_group_h h, uid_t uid);
static bool __app_group_is_sub_app(app_group_h h);

static int __wl_init(void)
{
	if (!display) {
		display = amd_wayland_get_display();
		if (!display) {
			LOGE("Failed to get display");
			return -1;
		}
	}

	if (!tz_policy)
		return -1;

	tz_policy_initialized = 1;

	return 0;
}

static void __lower_window(int wid)
{
	if (!tz_policy_initialized) {
		if (__wl_init() < 0) {
			LOGE("__wl_init() failed");
			return;
		}
	}

	tizen_policy_lower_by_res_id(tz_policy, wid);
	wl_display_roundtrip(display);
}

static void __attach_window(int parent_wid, int child_wid)
{
	if (!tz_policy_initialized) {
		if (__wl_init() < 0) {
			LOGE("__wl_init() failed");
			return;
		}
	}

	tizen_policy_set_transient_for(tz_policy, child_wid, parent_wid);
	wl_display_roundtrip(display);
}

static void __detach_window(int child_wid)
{
	if (!tz_policy_initialized) {
		if (__wl_init() < 0) {
			LOGE("__wl_init() failed");
			return;
		}
	}

	tizen_policy_unset_transient_for(tz_policy, child_wid);
	wl_display_roundtrip(display);
}

static void __activate_below(int wid, int below_wid)
{
	if (!tz_policy_initialized) {
		if (__wl_init() < 0) {
			LOGE("__wl_init() failed");
			return;
		}
	}

	tizen_policy_activate_below_by_res_id(tz_policy, below_wid, wid);
	wl_display_roundtrip(display);
}

static void __activate_above(int wid, int above_wid)
{
	if (!tz_policy_initialized) {
		if (__wl_init() < 0) {
			LOGE("__wl_init() failed");
			return;
		}
	}

	tizen_policy_activate_above_by_res_id(tz_policy, above_wid, wid);
	wl_display_roundtrip(display);
}

static gint __comp_pid(gconstpointer a, gconstpointer b)
{
	app_group_context_t *ac1 = (app_group_context_t *)a;

	return ac1->pid - GPOINTER_TO_INT(b);
}

static void __list_destroy_cb(gpointer data)
{
	free(data);
}

static GList *__get_context_node(int pid)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	app_group_context_t *ac;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		i = g_list_first(list);
		while (i != NULL) {
			ac = (app_group_context_t *)i->data;
			if (ac && ac->pid == pid)
				return i;

			i = g_list_next(i);
		}
	}

	return NULL;
}

app_group_h _app_group_find(int pid)
{
	GList *node = __get_context_node(pid);

	if (!node)
		node = __get_context_node(getpgid(pid));

	return node;
}

static bool __app_group_is_leader(app_group_h h)
{
	if (!h)
		return false;

	if (g_list_first(h) == h)
		return true;

	return false;
}

static gboolean __hash_table_cb(gpointer key, gpointer value,
		gpointer user_data)
{
	int pid = GPOINTER_TO_INT(user_data);
	GList *list = (GList *)value;
	GList *itr = g_list_first(list);
	app_group_context_t *ac;

	while (itr != NULL) {
		ac = (app_group_context_t *)itr->data;
		if (ac && ac->pid == pid) {
			free(ac);
			list = g_list_delete_link(list, itr);
			if (g_list_length(list) == 0) {
				g_list_free_full(list, __list_destroy_cb);
				return TRUE;
			} else {
				return FALSE;
			}
		}
		itr = g_list_next(itr);
	}

	return FALSE;
}

static void __prepare_to_suspend_services(int pid, uid_t uid)
{
	int ret;
	int dummy = 0;

	LOGD("[__SUSPEND__] pid: %d, uid: %d", pid, uid);
	ret = aul_sock_send_raw(pid, uid, APP_SUSPEND, (unsigned char *)&dummy,
			sizeof(int), AUL_SOCK_NOREPLY);
	if (ret < 0)
		LOGE("error on suspend service for pid: %d", pid);
}

static void __prepare_to_wake_services(int pid, uid_t uid)
{
	int ret;
	int dummy = 0;

	LOGD("[__SUSPEND__] pid: %d, uid: %d", pid, uid);
	ret = aul_sock_send_raw(pid, uid, APP_WAKE, (unsigned char *)&dummy,
			sizeof(int), AUL_SOCK_NOREPLY);
	if (ret < 0)
		LOGE("error on wake service for pid: %d", pid);
}

static void __set_flag(GList *list, int cpid, int flag, bool force)
{
	app_group_context_t *ac;
	amd_app_status_h app_status;
	amd_appinfo_h ai;
	const char *appid;
	const char *pkgid;
	bool bg_allowed;
	uid_t uid;

	while (list) {
		ac = (app_group_context_t *)list->data;
		if (ac && (ac->fg != flag || force)) {
			app_status = amd_app_status_find_by_pid(ac->pid);
			appid = amd_app_status_get_appid(app_status);
			uid = amd_app_status_get_uid(app_status);
			ai = amd_appinfo_find(uid, appid);
			pkgid = amd_appinfo_get_value(ai, AMD_AIT_PKGID);
			bg_allowed = amd_suspend_is_allowed_background(ai);
			if (flag) {
				LOGD("Send FG signal %s", appid);
				aul_send_app_status_change_signal(ac->pid,
						appid, pkgid, STATUS_FOREGROUND,
						APP_TYPE_UI);
				if (!bg_allowed) {
					amd_app_status_find_service_apps(
						app_status,
						STATUS_VISIBLE,
						__prepare_to_wake_services,
						false);
				}
			} else {
				LOGD("send BG signal %s", appid);
				aul_send_app_status_change_signal(ac->pid,
						appid, pkgid, STATUS_BACKGROUND,
						APP_TYPE_UI);
				if (!bg_allowed) {
					amd_app_status_find_service_apps(
						app_status,
						STATUS_BG,
						__prepare_to_suspend_services,
						true);
					if (force && cpid == ac->pid) {
						__prepare_to_suspend_services(
								ac->pid, uid);
						amd_suspend_add_timer(ac->pid);
					}
				}
			}
			ac->fg = flag;
		}
		list = g_list_next(list);
	}
}

static void __set_fg_flag(int cpid, int flag, bool force)
{
	int lpid = _app_group_get_leader_pid(_app_group_find(cpid));
	GList *i = __get_context_node(lpid);

	if (!i)
		return;

	__set_flag(i, cpid, flag, force);
}

static bool __is_visible(int cpid)
{
	int lpid = _app_group_get_leader_pid(_app_group_find(cpid));
	GList *i = __get_context_node(lpid);
	app_group_context_t *ac;

	if (!i)
		return false;

	i = g_list_first(i);
	while (i) {
		ac = (app_group_context_t *)i->data;
		if (ac && ac->status == STATUS_VISIBLE)
			return true;

		i = g_list_next(i);
	}

	return false;
}

static bool __can_attach_window(bundle *b, const char *appid,
		app_group_launch_mode *launch_mode, uid_t uid)
{
	const char *str;
	const char *mode;
	amd_appinfo_h ai;

	ai = amd_appinfo_find(uid, appid);
	mode = amd_appinfo_get_value(ai, AMD_AIT_LAUNCH_MODE);
	if (mode == NULL)
		*launch_mode = APP_GROUP_LAUNCH_MODE_SINGLE;
	else if (strcmp(mode, "caller") == 0)
		*launch_mode = APP_GROUP_LAUNCH_MODE_CALLER;
	else if (strcmp(mode, "single") == 0)
		*launch_mode = APP_GROUP_LAUNCH_MODE_SINGLE;
	else if (strcmp(mode, "group") == 0)
		*launch_mode = APP_GROUP_LAUNCH_MODE_GROUP;

	switch (*launch_mode) {
	case APP_GROUP_LAUNCH_MODE_CALLER:
		LOGD("launch mode from db is caller");
		str = bundle_get_val(b, APP_SVC_K_LAUNCH_MODE);
		if (str != NULL && strncmp(str, "group", 5) == 0)
			return true;
		break;
	case APP_GROUP_LAUNCH_MODE_GROUP:
		return true;
	case APP_GROUP_LAUNCH_MODE_SINGLE:
		return false;
	}

	return false;
}

static bool __can_be_leader(bundle *b)
{
	const char *str;

	str = bundle_get_val(b, AUL_SVC_K_CAN_BE_LEADER);
	if (str != NULL && strcmp(str, "true") == 0)
		return true;

	return false;
}

static int __get_caller_pid(bundle *kb)
{
	const char *pid_str;
	int pid;

	pid_str = bundle_get_val(kb, AUL_K_ORG_CALLER_PID);
	if (pid_str)
		goto end;

	pid_str = bundle_get_val(kb, AUL_K_CALLER_PID);
	if (pid_str == NULL)
		return -1;

end:
	pid = atoi(pid_str);
	if (pid <= 1)
		return -1;

	return pid;
}

static app_group_context_t *__detach_context_from_recycle_bin(int pid)
{
	GList *iter = recycle_bin;
	app_group_context_t *ac;

	while (iter) {
		ac = (app_group_context_t *)iter->data;
		if (ac && ac->pid == pid) {
			recycle_bin = g_list_delete_link(recycle_bin, iter);
			return ac;
		}

		iter = g_list_next(iter);
	}

	return NULL;
}

static int __app_group_get_pid(app_group_h h)
{
	app_group_context_t *context;

	if (!h)
		return -1;

	context = h->data;

	return context->pid;
}

static void __group_remove(app_group_h h)
{
	GList *prev = g_list_previous(h);
	int pid = __app_group_get_pid(h);

	g_hash_table_foreach_remove(app_group_hash, __hash_table_cb,
			GINT_TO_POINTER(pid));

	if (!prev)
		__app_group_set_status(prev, -1, false);
}

static bool __can_recycle(app_group_h h)
{
	app_group_context_t *context = h->data;

	if (context)
		return context->recycle;

	return false;
}

static app_group_context_t *__context_dup(const app_group_context_t *context)
{
	app_group_context_t *dup;

	if (!context) {
		LOGE("context is NULL.");
		return NULL;
	}

	dup = malloc(sizeof(app_group_context_t));
	if (!dup) {
		LOGE("out of memory");
		return NULL;
	}

	memcpy(dup, context, sizeof(app_group_context_t));
	return dup;
}

static void __do_recycle(app_group_context_t *context)
{
	const char *appid;
	const char *pkgid;
	amd_appinfo_h ai;
	amd_app_status_h app_status;
	uid_t uid;

	app_status = amd_app_status_find_by_pid(context->pid);
	uid = amd_app_status_get_uid(app_status);

	if (context->fg) {
		appid = amd_app_status_get_appid(app_status);
		ai = amd_appinfo_find(uid, appid);
		pkgid = amd_appinfo_get_value(ai, AMD_AIT_PKGID);

		LOGD("send_signal BG %s", appid);
		aul_send_app_status_change_signal(context->pid, appid, pkgid,
				STATUS_BACKGROUND, APP_TYPE_UI);
		amd_app_status_find_service_apps(app_status, STATUS_BG,
				__prepare_to_suspend_services, true);
		context->fg = false;
	}
	recycle_bin = g_list_append(recycle_bin, context);
	amd_noti_send("app_group.do_recycle.end", context->pid, uid, NULL, NULL);
}

static void __app_group_remove(app_group_h h)
{
	app_group_context_t *context;
	int pid;

	if (!h)
		return;

	pid = __app_group_get_pid(h);
	__group_remove(h);
	context = __detach_context_from_recycle_bin(pid);
	if (context)
		free(context);
}

static int __find_second_leader(int lpid)
{
	app_group_context_t *ac;
	GList *list;

	list = (GList *)g_hash_table_lookup(app_group_hash,
			GINT_TO_POINTER(lpid));
	if (list != NULL) {
		list = g_list_next(list);
		if (list != NULL) {
			ac = (app_group_context_t *)list->data;
			if (ac && ac->can_be_leader) {
				LOGW("found the second leader, lpid: %d, pid: %d",
						lpid, ac->pid);
				return ac->pid;
			}
		}
	}

	return -1;
}

static void __remove_leader_pid(int lpid)
{
	app_group_context_t *ac;
	GList *next;
	GList *list;

	list = (GList *)g_hash_table_lookup(app_group_hash,
			GINT_TO_POINTER(lpid));
	if (list != NULL) {
		next = g_list_next(list);
		if (next != NULL) {
			ac = (app_group_context_t *)list->data;
			if (ac)
				free(ac);
			list = g_list_delete_link(list, list);
			ac = (app_group_context_t *)next->data;
			g_hash_table_insert(app_group_hash,
					GINT_TO_POINTER(ac->pid), next);
			g_hash_table_remove(app_group_hash,
					GINT_TO_POINTER(lpid));
		}
	}
}

static int __get_next_caller_pid(app_group_h h)
{
	app_group_context_t *ac;

	if (!h)
		return -1;

	h = g_list_next(h);
	if (!h)
		return -1;

	ac = h->data;

	return ac->caller_pid;
}

static bool __can_reroute(app_group_h h)
{
	app_group_context_t *ac;

	if (!h)
		return false;

	ac = h->data;

	return ac->reroute;
}

static void __reroute(app_group_h h)
{
	GList *before;
	GList *after;
	app_group_context_t *ac1;
	app_group_context_t *ac2;
	GList *list = h;

	if (!list)
		return;

	before = g_list_previous(list);
	after = g_list_next(list);
	if (!before || !after)
		return;

	LOGD("reroute");
	ac1 = (app_group_context_t *)before->data;
	ac2 = (app_group_context_t *)after->data;
	__attach_window(ac1->wid, ac2->wid);
}

static void __app_group_remove_full(app_group_h h, uid_t uid)
{
	int pid;
	int caller_pid;

	if (!h)
		return;

	pid = __app_group_get_pid(h);
	if (__app_group_is_leader(h)) {
		LOGW("app_group_leader_app, pid: %d", pid);
		if (__find_second_leader(pid) == -1) {
			__app_group_clear_top(h, uid);
			__app_group_remove(h);
		} else {
			__remove_leader_pid(pid);
		}
	} else if (__app_group_is_sub_app(h)) {
		LOGW("app_group_sub_app, pid: %d", pid);
		caller_pid = __get_next_caller_pid(h);
		if (__can_reroute(h)
				|| (caller_pid > 0 && caller_pid != pid)) {
			LOGW("app_group reroute");
			__reroute(h);
		} else {
			LOGW("app_group clear top");
			__app_group_clear_top(h, uid);
		}
		__app_group_remove(h);
	}
}

static void __app_group_remove_from_recycle_bin(int pid)
{
	app_group_context_t *context = __detach_context_from_recycle_bin(pid);

	if (context)
		free(context);
}

int _app_group_get_window(app_group_h h)
{
	app_group_context_t *context;

	if (!h)
		return -1;

	context = h->data;
	if (context)
		return context->wid;

	return -1;
}

static int __app_group_set_window(app_group_h h, int wid)
{
	GList *i = h;
	GList *j;
	int previous_wid = 0;
	int next_wid = 0;
	int caller_wid;
	app_group_context_t *ac;
	app_group_context_t *prev_ac;
	app_group_context_t *next_ac;

	if (!i)
		return -1;

	ac = i->data;
	ac->wid = wid;

	j = g_list_previous(i);
	if (j) {
		prev_ac = j->data;
		previous_wid = prev_ac->wid;
	}

	j = g_list_next(i);
	if (j) {
		next_ac = j->data;
		next_wid = next_ac->wid;
	}

	if (previous_wid != 0)
		__attach_window(previous_wid, wid);

	if (ac->can_shift && ac->caller_pid > 0) {
		caller_wid = _app_group_get_window(
				_app_group_find(ac->caller_pid));
		if (caller_wid != 0)
			__attach_window(caller_wid, wid);
	}

	if (next_wid != 0)
		__attach_window(wid, next_wid);

	return 0;
}

static void __app_group_clear_top(app_group_h h, uid_t uid)
{
	int wid;
	GList *itr;
	GList *cur;

	if (!h)
		return;

	itr = g_list_last(h);
	while (itr != NULL && itr != h) {
		cur = itr;
		itr = g_list_previous(itr);
		wid = _app_group_get_window(cur);
		__detach_window(wid);
		aul_send_app_terminate_request_signal(__app_group_get_pid(cur),
				NULL, NULL, NULL);
		amd_launch_term_sub_app(__app_group_get_pid(cur), uid);
		__app_group_remove(cur);
	}
}

static bool __app_group_is_group_app(bundle *kb, uid_t uid)
{
	const char *str;
	const char *mode;
	const char *appid;
	amd_appinfo_h ai;

	if (kb == NULL)
		return false;

	appid = bundle_get_val(kb, AUL_K_APPID);
	if (appid == NULL)
		return false;

	ai = amd_appinfo_find(uid, appid);
	mode = amd_appinfo_get_value(ai, AMD_AIT_LAUNCH_MODE);
	if (mode != NULL && strcmp(mode, "caller") == 0) {
		str = bundle_get_val(kb, APP_SVC_K_LAUNCH_MODE);
		if (str != NULL && strcmp(str, "group") == 0)
			return true;
	} else if (mode != NULL && strcmp(mode, "group") == 0) {
		return true;
	}

	return false;
}

static void __app_group_get_leader_pids(int *cnt, int **pids)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	int size = g_hash_table_size(app_group_hash);
	int *leader_pids;
	int i;

	if (size > 0) {
		leader_pids = (int *)malloc(sizeof(int) * size);
		if (leader_pids == NULL) {
			LOGE("out of memory");
			*cnt = 0;
			*pids = NULL;
			return;
		}

		g_hash_table_iter_init(&iter, app_group_hash);
		i = 0;
		while (g_hash_table_iter_next(&iter, &key, &value)) {
			leader_pids[i] = GPOINTER_TO_INT(key);
			i++;
		}

		*cnt = size;
		*pids = leader_pids;
	} else {
		*cnt = 0;
		*pids = NULL;
	}
}

void _app_group_get_group_pids(int leader_pid, int *cnt, int **pids)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	int size;
	int *pid_array;
	int j;
	app_group_context_t *ac;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		if (GPOINTER_TO_INT(key) == leader_pid) {
			list = (GList *)value;
			i = g_list_first(list);
			size = g_list_length(list);
			if (size > 0) {
				j = 0;
				pid_array = (int *)malloc(sizeof(int) * size);
				if (pid_array == NULL) {
					LOGE("out of memory");
					*cnt = 0;
					*pids = NULL;
					return;
				}

				while (i != NULL) {
					ac = (app_group_context_t *)i->data;
					pid_array[j] = ac->pid;
					i = g_list_next(i);
					j++;
				}

				*cnt = size;
				*pids = pid_array;
			} else {
				*cnt = 0;
				*pids = NULL;
			}
			return;
		}
	}

	*cnt = 0;
	*pids = NULL;
}

static bool __app_group_is_sub_app(app_group_h h)
{
	if (!h)
		return false;

	if (g_list_previous(h))
		return true;

	return false;
}

int _app_group_get_leader_pid(app_group_h h)
{
	GList *list = h;
	int lpid;
	app_group_context_t *ac;

	if (!h)
		return -1;

	list = g_list_first(list);
	ac = list->data;
	lpid = ac->pid;

	return lpid;
}

static void __set_status(app_group_context_t *ac, app_group_context_t *last_ac,
		int lpid, int pid, int status, bool force)
{
	const char *pkgid;
	amd_app_status_h app_status;

	if (status > 0)
		ac->status = status;

	if (last_ac->wid != 0 || status == STATUS_VISIBLE || force == TRUE) {
		if (__is_visible(pid)) {
			__set_fg_flag(pid, 1, force);
			if (!ac->group_sig && lpid != pid) {
				app_status = amd_app_status_find_by_pid(pid);
				pkgid = amd_app_status_get_pkgid(app_status);
				LOGD("send group signal %d", pid);
				aul_send_app_group_signal(lpid, pid, pkgid);
				ac->group_sig = 1;
			}
		} else {
			__set_fg_flag(pid, 0, force);
		}
	}
}

static int __app_group_set_status(app_group_h h, int status, bool force)
{
	GList *i = h;
	app_group_context_t *ac;
	app_group_context_t *last_ac;
	app_group_context_t *first_ac;
	int lpid;
	int pid;

	if (!i)
		return -1;

	pid = __app_group_get_pid(h);
	ac = i->data;
	i = g_list_last(i);
	last_ac = i->data;
	i = g_list_first(i);
	first_ac = i->data;
	lpid = first_ac->pid;
	__set_status(ac, last_ac, lpid, pid, status, force);

	return 0;
}

static bool __app_group_get_fg_flag(app_group_h h)
{
	app_group_context_t *ac;

	if (!h)
		return false;

	ac = h->data;

	return ac->fg;
}

static int __app_group_can_start_app(const char *appid, bundle *b,
		bool *can_attach, int *lpid, app_group_launch_mode *mode,
		uid_t uid)
{
	const char *val;
	int caller_pid;
	int caller_wid;
	app_group_h h;
	int ret = 0;

	*can_attach = false;

	if (__can_attach_window(b, appid, mode, uid)) {
		*can_attach = true;
		val = bundle_get_val(b, AUL_K_ORG_CALLER_PID);
		if (val == NULL)
			val = bundle_get_val(b, AUL_K_CALLER_PID);

		if (val == NULL) {
			LOGE("no caller pid");
			ret = -1;
			goto err;
		}

		caller_pid = atoi(val);
		h = _app_group_find(caller_pid);
		*lpid = _app_group_get_leader_pid(h);
		if (*lpid != -1) {
			caller_wid = _app_group_get_window(h);
			if (caller_wid == 0) {
				LOGW("caller(%d) window wasn't ready",
						caller_pid);
				if (__can_be_leader(b))
					*can_attach = false;
				else
					*can_attach = true;
			}
		} else {
			LOGE("no lpid");
			if (__can_be_leader(b)) {
				*can_attach = false;
			} else {
				ret = -1;
				goto err;
			}
		}
	}

err:
	__launch_context.can_attach = *can_attach;
	__launch_context.mode = *mode;
	__launch_context.lpid = *lpid;
	LOGW("[__APP_GROUP__] can_attach(%d), mode(%d), lpid(%d)",
			__launch_context.can_attach,
			__launch_context.mode,
			__launch_context.lpid);

	return ret;
}

static app_group_context_t *__group_add(int leader_pid, int pid,
		app_group_launch_mode mode, int caller_pid, bool can_shift,
		bool recycle)
{
	app_group_context_t *ac = NULL;
	GList *list;
	GList *tmp_list;
	app_group_h h;

	ac = __detach_context_from_recycle_bin(pid);
	if (ac == NULL) {
		ac = calloc(1, sizeof(app_group_context_t));
		if (ac == NULL) {
			LOGE("out of memory");
			return NULL;
		}
		ac->pid = pid;
		ac->wid = 0;
		ac->fg = false;
		ac->can_be_leader = false;
		ac->reroute = false;
		ac->launch_mode = mode;
		ac->caller_pid = caller_pid;
		ac->can_shift = can_shift;
		ac->recycle = recycle;
	}

	if (leader_pid == pid || ac->recycle)
		ac->group_sig = true;
	else
		ac->group_sig = false;

	list = (GList *)g_hash_table_lookup(app_group_hash,
			GINT_TO_POINTER(leader_pid));
	if (list != NULL) {
		tmp_list = g_list_find_custom(list, GINT_TO_POINTER(pid),
				__comp_pid);
		if (tmp_list != NULL) {
			LOGE("pid exist");
			free(ac);
			return NULL;
		}
	}

	list = g_list_append(list, ac);
	g_hash_table_insert(app_group_hash, GINT_TO_POINTER(leader_pid), list);

	if (ac->wid != 0) {
		h = _app_group_find(pid);
		__app_group_set_window(h, ac->wid);
	}

	return ac;
}

static int __set_hint(app_group_context_t *ac, bundle *kb)
{
	char *str_leader = NULL;
	char *str_reroute = NULL;

	if (!kb || !ac)
		return -1;

	bundle_get_str(kb, AUL_SVC_K_CAN_BE_LEADER, &str_leader);
	bundle_get_str(kb, AUL_SVC_K_REROUTE, &str_reroute);

	if (str_leader && !strcmp(str_leader, "true"))
		ac->can_be_leader = true;
	if (str_reroute && !strcmp(str_reroute, "true"))
		ac->reroute = true;
	return 0;
}

static void __app_group_start_app(int pid, bundle *b, int lpid, bool can_attach,
		app_group_launch_mode mode)
{
	int caller_pid = __get_caller_pid(b);
	bool can_shift = false;
	bool recycle = false;
	const char *str;
	app_group_context_t *ac;

	LOGD("app_group_start_app");

	str = bundle_get_val(b, AUL_SVC_K_SHIFT_WINDOW);
	if (str != NULL && strcmp(str, "true") == 0)
		can_shift = true;

	str = bundle_get_val(b, AUL_SVC_K_RECYCLE);
	if (str != NULL && strcmp(str, "true") == 0)
		recycle = true;

	if (can_attach)
		ac = __group_add(lpid, pid, mode, caller_pid, false, recycle);
	else
		ac = __group_add(pid, pid, mode, caller_pid, can_shift, false);
	__set_hint(ac, b);
}

static void __app_group_lower(app_group_h h, bool *exit)
{
	app_group_context_t *ac;

	if (!h)
		return;

	ac = h->data;
	if (__app_group_is_sub_app(h)) {
		if (__can_recycle(h) && __can_reroute(h)) {
			__reroute(h);
			if (ac->wid != 0)
				__detach_window(ac->wid);

			ac = __context_dup(ac);
			__group_remove(h);
			__do_recycle(ac);
			*exit = false;
		} else {
			*exit = true;
		}

		return;
	}

	*exit = false;
	if (ac->can_shift) {
		__detach_window(ac->wid);
		ac->can_shift = false;
		__lower_window(ac->wid);
	}
}

static void __app_group_restart_app(app_group_h h, bundle *b)
{
	app_group_context_t *ac;
	const char *pid_str;
	int cwid;

	if (!b || !h)
		return;

	ac = h->data;
	ac->caller_pid = __get_caller_pid(b);
	if (ac->can_shift) {
		if (ac->wid != 0)
			__detach_window(ac->wid);
		ac->can_shift = false;
	}

	pid_str = bundle_get_val(b, AUL_SVC_K_SHIFT_WINDOW);
	if (pid_str && !strcmp(pid_str, "true")) {
		ac->can_shift = true;
		if (ac->wid != 0) {
			if (ac->caller_pid > 0) {
				cwid = _app_group_get_window(
					_app_group_find(ac->caller_pid));
				if (cwid != 0)
					__attach_window(cwid, ac->wid);
				else
					LOGE("invalid caller wid");
			} else {
				LOGE("invalid caller pid");
			}
		}
	}
}

static int __app_group_find_pid_from_recycle_bin(const char *appid)
{
	app_group_context_t *ac;
	amd_app_status_h app_status;
	const char *appid_from_bin;
	GList *iter = recycle_bin;

	while (iter) {
		ac = (app_group_context_t *)iter->data;
		app_status = amd_app_status_find_by_pid(ac->pid);
		appid_from_bin = amd_app_status_get_appid(app_status);
		if (appid && appid_from_bin && !strcmp(appid, appid_from_bin))
			return ac->pid;

		iter = g_list_next(iter);
	}

	return -1;
}

static void __app_group_get_idle_pids(int *cnt, int **pids)
{
	GList *iter = recycle_bin;
	int idle_cnt = g_list_length(iter);
	int *idle_pids;
	int i = 0;
	app_group_context_t *ac;

	if (idle_cnt <= 0) {
		*cnt = 0;
		*pids = NULL;
		return;
	}

	idle_pids = (int *)malloc(sizeof(int) * idle_cnt);
	if (idle_pids == NULL) {
		LOGE("Out-of-memory");
		*cnt = 0;
		*pids = NULL;
		return;
	}

	while (iter) {
		ac = (app_group_context_t *)iter->data;
		idle_pids[i] = ac->pid;
		iter = g_list_next(iter);
		i++;
	}

	*cnt = idle_cnt;
	*pids = idle_pids;
}

static int __app_group_activate_below(app_group_h h, const char *below_appid)
{
	app_group_context_t *context;
	int wid;
	int tpid;
	GList *list;
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	amd_app_status_h app_status;
	const char *appid;

	if (!h) {
		LOGE("Invalid handle");
		return -1;
	}

	context = h->data;
	if (context->wid == 0) {
		LOGE("Caller wid was 0");
		return -1;
	}

	if (!below_appid) {
		LOGE("below_appid was null");
		return -1;
	}

	wid = context->wid;
	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		tpid = GPOINTER_TO_INT(key);
		app_status = amd_app_status_find_by_pid(tpid);
		appid = amd_app_status_get_appid(app_status);
		if (appid && strcmp(appid, below_appid) == 0) {
			list = (GList *)value;
			context  = (app_group_context_t *)list->data;
			__activate_below(wid, context->wid);
			return 0;
		}
	}

	LOGE("Failed to find available appid to move");
	return -1;
}

static int __app_group_activate_above(app_group_h h, const char *above_appid)
{
	app_group_context_t *context;
	int wid;
	int tpid;
	GList *list;
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	amd_app_status_h app_status;
	const char *appid;

	if (!h) {
		LOGE("Invalid handle");
		return -1;
	}

	context = h->data;
	if (context->wid == 0) {
		LOGE("Caller wid was 0");
		return -1;
	}

	if (!above_appid) {
		LOGE("below_appid was null");
		return -1;
	}

	wid = context->wid;
	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		tpid = GPOINTER_TO_INT(key);
		app_status = amd_app_status_find_by_pid(tpid);
		appid = amd_app_status_get_appid(app_status);
		if (appid && strcmp(appid, above_appid) == 0) {
			list = (GList *)value;
			context  = (app_group_context_t *)list->data;
			__activate_above(wid, context->wid);
			return 0;
		}
	}

	LOGE("Failed to find available appid to move");
	return -1;
}

static int __app_group_attach(const char *parent_appid, const char *child_appid,
		uid_t uid)
{
	amd_app_status_h status;
	int ppid;
	int cpid;
	int pwid;
	int cwid;

	status = amd_app_status_find_by_appid(parent_appid, uid);
	if (!status) {
		LOGE("parent app is not running %s", parent_appid);
		return -1;
	}

	ppid = amd_app_status_get_pid(status);
	status = amd_app_status_find_by_appid(child_appid, uid);
	if (!status) {
		LOGE("child app is not running %s", child_appid);
		return -1;
	}

	pwid = _app_group_get_window(_app_group_find(ppid));
	if (pwid == 0) {
		LOGE("window wasn't ready - ppid(%d)", ppid);
		return -1;
	}

	cpid = amd_app_status_get_pid(status);
	cwid = _app_group_get_window(_app_group_find(cpid));
	if (cwid == 0) {
		LOGE("window wasn't ready - cpid(%d)", cpid);
		return -1;
	}

	__attach_window(pwid, cwid);

	return 0;
}

static int __app_group_detach(const char *child_appid, uid_t uid)
{
	amd_app_status_h status;
	int cpid;
	int cwid;

	status = amd_app_status_find_by_appid(child_appid, uid);
	if (!status) {
		LOGE("child app is not running %s", child_appid);
		return -1;
	}

	cpid = amd_app_status_get_pid(status);
	cwid = _app_group_get_window(_app_group_find(cpid));
	if (cwid == 0) {
		LOGE("window wasn't ready : %d", cwid);
		return -1;
	}

	__detach_window(cwid);

	return 0;
}

static int __dispatch_app_group_get_window(amd_request_h req)
{
	char *buf;
	int pid = -1;
	int wid;
	app_group_h app_group;
	bundle *b;

	b = amd_request_get_bundle(req);
	if (!b) {
		LOGE("[__APP_GROUP__] Failed to get bundle");
		amd_request_send_result(req, -1);
		return -1;
	}

	bundle_get_str(b, AUL_K_PID, &buf);
	if (buf && isdigit(buf[0]))
		pid = atoi(buf);

	if (pid <= 1) {
		LOGE("[__APP_GROUP__] Invalid process ID(%d)", pid);
		amd_request_send_result(req, -1);
		return -1;
	}

	pid = _status_get_effective_pid(pid);
	if (pid < 0) {
		amd_request_send_result(req, -1);
		return -1;
	}

	app_group = _app_group_find(pid);
	if (!app_group) {
		LOGE("[__APP_GROUP__] Failed to find app group");
		amd_request_send_result(req, -1);
		return -1;
	}

	wid = _app_group_get_window(app_group);
	if (wid < 0)
		LOGE("[__APP_GROUP__] Failed to get window");

	amd_request_send_result(req, wid);

	return 0;
}

static int __dispatch_app_group_set_window(amd_request_h req)
{
	char *buf;
	int pid = amd_request_get_pid(req);
	uid_t uid = amd_request_get_target_uid(req);
	int wid = -1;
	int ret;
	app_group_h app_group;
	bundle *b;

	b = amd_request_get_bundle(req);
	if (!b) {
		LOGE("[__APP_GROUP__] Failed to get bundle");
		return -1;
	}

	bundle_get_str(b, AUL_K_WID, &buf);
	if (buf && isdigit(buf[0]))
		wid = atoi(buf);

	if (wid < 0) {
		LOGE("[__APP_GROUP__] Failed to get window ID");
		return -1;
	}

	pid = _status_get_effective_pid(pid);
	if (pid < 0)
		return -1;

	app_group = _app_group_find(pid);
	if (!app_group) {
		LOGE("[__APP_GROUP__] Failed to find app group");
		return -1;
	}

	ret = __app_group_set_window(_app_group_find(pid), wid);
	if (ret < 0) {
		LOGE("[__APP_GROUP__] Failed to set window. pid(%d), wid(%d)",
				pid, wid);
		return -1;
	}

	_screen_connector_add_app_screen(pid, wid, NULL, uid);
	amd_noti_send("app_group.window.set", pid, wid, NULL, NULL);
	LOGI("[__APP_GROUP__] pid(%d), wid(%d), result(%d)", pid, wid, ret);

	return ret;
}

static int __dispatch_app_group_get_fg_flag(amd_request_h req)
{
	char *buf;
	int pid = -1;
	bool fg;
	app_group_h app_group;
	bundle *b;

	b = amd_request_get_bundle(req);
	if (!b) {
		LOGE("[__APP_GROUP__] Failed to get bundle");
		amd_request_send_result(req, 0);
		return -1;
	}

	bundle_get_str(b, AUL_K_PID, &buf);
	if (buf && isdigit(buf[0]))
		pid = atoi(buf);

	pid = _status_get_effective_pid(pid);
	if (pid <= 1) {
		LOGE("[__APP_GROUP__] Invalid process ID(%d)", pid);
		amd_request_send_result(req, 0);
		return -1;
	}

	app_group = _app_group_find(pid);
	if (!app_group) {
		LOGE("[__APP_GROUP__] Failed to find app group. pid(%d)", pid);
		amd_request_send_result(req, 0);
		return -1;
	}

	fg = __app_group_get_fg_flag(_app_group_find(pid));
	amd_request_send_result(req, (int)fg);

	return 0;
}

static int __dispatch_app_group_clear_top(amd_request_h req)
{
	int pid = amd_request_get_pid(req);
	uid_t uid = amd_request_get_target_uid(req);
	app_group_h app_group;

	pid = _status_get_effective_pid(pid);
	if (pid < 0) {
		amd_request_send_result(req, 0);
		return -1;
	}

	app_group = _app_group_find(pid);
	if (!app_group) {
		LOGE("[__APP_GROUP__] Failed to find app group");
		amd_request_send_result(req, 0);
		return -1;
	}

	__app_group_clear_top(app_group, uid);
	amd_request_send_result(req, 0);

	return 0;
}

static int __dispatch_app_group_get_leader_pid(amd_request_h req)
{
	char *buf;
	int pid = -1;
	int lpid;
	bundle *b;
	app_group_h app_group;

	b = amd_request_get_bundle(req);
	if (!b) {
		LOGE("[__APP_GROUP__] Failed to get bundle");
		amd_request_send_result(req, -1);
		return -1;
	}

	bundle_get_str(b, AUL_K_PID, &buf);
	if (buf && isdigit(buf[0]))
		pid = atoi(buf);

	pid = _status_get_effective_pid(pid);
	if (pid <= 1) {
		LOGE("[__APP_GROUP__] Failed to get process ID");
		amd_request_send_result(req, -1);
		return -1;
	}

	app_group = _app_group_find(pid);
	if (!app_group) {
		LOGE("[__APP_GROUP__] Failed to find app group. pid(%d)", pid);
		amd_request_send_result(req, -1);
		return -1;
	}

	lpid = _app_group_get_leader_pid(app_group);
	amd_request_send_result(req, lpid);
	LOGI("[__APP_GROUP__] pid(%d), lpid(%d)", pid, lpid);

	return 0;
}

static int __dispatch_app_group_get_leader_pids(amd_request_h req)
{
	int cnt;
	int *pids;
	unsigned char empty[1] = {0,};

	__app_group_get_leader_pids(&cnt, &pids);

	if (pids == NULL || cnt == 0) {
		amd_request_send_raw(req, APP_GROUP_GET_LEADER_PIDS, empty, 0);
	} else {
		amd_request_send_raw(req, APP_GROUP_GET_LEADER_PIDS,
				(unsigned char *)pids, cnt * sizeof(int));
	}

	if (pids != NULL)
		free(pids);

	LOGI("[__APP_GROUP__] count(%d)", cnt);

	return 0;
}

static int __dispatch_app_group_get_idle_pids(amd_request_h req)
{
	int cnt;
	int *pids;
	unsigned char empty[1] = {0,};

	__app_group_get_idle_pids(&cnt, &pids);
	if (pids == NULL || cnt == 0) {
		amd_request_send_raw(req, APP_GROUP_GET_IDLE_PIDS, empty, 0);
	} else {
		amd_request_send_raw(req, APP_GROUP_GET_IDLE_PIDS,
				(unsigned char *)pids, cnt * sizeof(int));
	}

	if (pids != NULL)
		free(pids);

	LOGI("[__APP_GROUP__] count(%d)", cnt);

	return 0;
}

static int __dispatch_app_group_get_group_pids(amd_request_h req)
{
	char *buf;
	int leader_pid = -1;
	int cnt;
	int *pids;
	unsigned char empty[1] = { 0 };
	bundle *b;

	b = amd_request_get_bundle(req);
	if (!b) {
		LOGE("[__APP_GROUP__] Failed to get bundle");
		amd_request_send_raw(req, APP_GROUP_GET_GROUP_PIDS, empty, 0);
		return -1;
	}

	bundle_get_str(b, AUL_K_LEADER_PID, &buf);
	if (buf && isdigit(buf[0]))
		leader_pid = atoi(buf);

	if (leader_pid <= 1) {
		LOGE("[__APP_GROUP__] Failed to get leader process ID");
		amd_request_send_raw(req, APP_GROUP_GET_GROUP_PIDS, empty, 0);
		return -1;
	}

	_app_group_get_group_pids(leader_pid, &cnt, &pids);
	if (pids == NULL || cnt == 0) {
		amd_request_send_raw(req, APP_GROUP_GET_GROUP_PIDS, empty, 0);
	} else {
		amd_request_send_raw(req, APP_GROUP_GET_GROUP_PIDS,
				(unsigned char *)pids, cnt * sizeof(int));
	}

	if (pids != NULL)
		free(pids);

	LOGI("[__APP_GROUP__] count(%d)", cnt);

	return 0;
}

static int __dispatch_app_group_lower(amd_request_h req)
{
	bool ret = false;
	int pid = amd_request_get_pid(req);
	app_group_h app_group;

	pid = _status_get_effective_pid(pid);
	if (pid < 0) {
		amd_request_send_result(req, -1);
		return -1;
	}

	app_group = _app_group_find(pid);
	if (!app_group) {
		LOGE("[__APP_GROUP__] Failed to find app group");
		amd_request_send_result(req, 0);
		return -1;
	}

	__app_group_lower(app_group, &ret);
	amd_request_send_result(req, (int)ret);

	return 0;
}

static int __dispatch_app_group_activate_below(amd_request_h req)
{
	char *buf = NULL;
	int ret;
	app_group_h app_group;
	bundle *b;
	int pid;

	b = amd_request_get_bundle(req);
	if (!b) {
		LOGE("[__APP_GROUP__] Failed to get bundle");
		amd_request_send_result(req, -1);
		return -1;
	}

	bundle_get_str(b, AUL_K_APPID, &buf);
	if (!buf) {
		LOGE("[__APP_GROUP__] Failed to get appid");
		amd_request_send_result(req, -1);
		return -1;
	}

	pid = _status_get_effective_pid(amd_request_get_pid(req));
	app_group = _app_group_find(pid);
	if (!app_group) {
		LOGE("[__APP_GROUP__] Failed to find app group");
		amd_request_send_result(req, -1);
		return -1;
	}

	ret = __app_group_activate_below(app_group, buf);
	amd_request_send_result(req, ret);
	LOGI("[__APP_GROUP__] pid(%d), appid(%s), result(%d)",
			pid, buf, ret);

	return 0;
}

static int __dispatch_app_group_activate_above(amd_request_h req)
{
	char *buf = NULL;
	int ret;
	app_group_h app_group;
	bundle *b;
	int pid;

	b = amd_request_get_bundle(req);
	if (!b) {
		LOGE("[__APP_GROUP__] Failed to get bundle");
		amd_request_send_result(req, -1);
		return -1;
	}

	bundle_get_str(b, AUL_K_APPID, &buf);
	if (!buf) {
		LOGE("[__APP_GROUP__] Failed to get appid");
		amd_request_send_result(req, -1);
		return -1;
	}

	pid = _status_get_effective_pid(amd_request_get_pid(req));
	app_group = _app_group_find(pid);
	if (!app_group) {
		LOGE("[__APP_GROUP__] Failed to find app group");
		amd_request_send_result(req, -1);
		return -1;
	}

	ret = __app_group_activate_above(app_group, buf);
	amd_request_send_result(req, ret);
	LOGI("[__APP_GROUP__] pid(%d), appid(%s), result(%d)",
			pid, buf, ret);

	return 0;
}

static int __dispatch_app_window_attach(amd_request_h req)
{
	bundle *b = amd_request_get_bundle(req);
	const char *parent_appid;
	const char *child_appid;
	int ret;
	uid_t uid = amd_request_get_target_uid(req);

	if (!b) {
		LOGE("[__APP_GROUP__] Invalid bundle");
		amd_request_send_result(req, -1);
		return -1;
	}

	parent_appid = bundle_get_val(b, AUL_K_PARENT_APPID);
	if (!parent_appid) {
		LOGE("[__APP_GROUP__] Invalid parameters");
		amd_request_send_result(req, -1);
		return -1;
	}

	child_appid = bundle_get_val(b, AUL_K_CHILD_APPID);
	if (!child_appid) {
		LOGE("[__APP_GROUP__] Invalid parameters");
		amd_request_send_result(req, -1);
		return -1;
	}

	ret = __app_group_attach(parent_appid, child_appid, uid);
	amd_request_send_result(req, ret);
	LOGI("[__APP_GROUP__] parent appid(%s), child appid(%s), result(%d)",
			parent_appid, child_appid, ret);

	return 0;
}

static int __dispatch_app_window_detach(amd_request_h req)
{
	bundle *b = amd_request_get_bundle(req);
	const char *child_appid;
	int ret;
	uid_t uid = amd_request_get_target_uid(req);

	if (!b) {
		LOGE("[__APP_GROUP__] Invalid bundle");
		amd_request_send_result(req, -1);
		return -1;
	}

	child_appid = bundle_get_val(b, AUL_K_CHILD_APPID);
	if (!child_appid) {
		LOGE("[__APP_GROUP__] Invalid parameters");
		amd_request_send_result(req, -1);
		return -1;
	}

	ret = __app_group_detach(child_appid, uid);
	amd_request_send_result(req, ret);
	LOGI("[__APP_GROUP__] child appid(%s), result(%d)", child_appid, ret);

	return 0;
}

static amd_request_cmd_dispatch __dispatch_table[] = {
	{
		.cmd = APP_GROUP_GET_WINDOW,
		.callback = __dispatch_app_group_get_window
	},
	{
		.cmd = APP_GROUP_SET_WINDOW,
		.callback = __dispatch_app_group_set_window
	},
	{
		.cmd = APP_GROUP_GET_FG,
		.callback = __dispatch_app_group_get_fg_flag
	},
	{
		.cmd = APP_GROUP_GET_LEADER_PID,
		.callback = __dispatch_app_group_get_leader_pid
	},
	{
		.cmd = APP_GROUP_GET_LEADER_PIDS,
		.callback = __dispatch_app_group_get_leader_pids
	},
	{
		.cmd = APP_GROUP_GET_GROUP_PIDS,
		.callback = __dispatch_app_group_get_group_pids
	},
	{
		.cmd = APP_GROUP_GET_IDLE_PIDS,
		.callback = __dispatch_app_group_get_idle_pids
	},
	{
		.cmd = APP_GROUP_LOWER,
		.callback = __dispatch_app_group_lower
	},
	{	.cmd = APP_GROUP_CLEAR_TOP,
		.callback = __dispatch_app_group_clear_top
	},
	{
		.cmd = APP_GROUP_ACTIVATE_BELOW,
		.callback = __dispatch_app_group_activate_below
	},
	{
		.cmd = APP_GROUP_ACTIVATE_ABOVE,
		.callback = __dispatch_app_group_activate_above
	},
	{
		.cmd = APP_WINDOW_ATTACH,
		.callback = __dispatch_app_window_attach
	},
	{	.cmd = APP_WINDOW_DETACH,
		.callback = __dispatch_app_window_detach
	},
};

static amd_cynara_checker __cynara_checkers[] = {
	{
		.cmd = APP_WINDOW_ATTACH,
		.checker = amd_cynara_simple_checker,
		.data = PRIVILEGE_PLATFORM
	},
	{
		.cmd = APP_WINDOW_DETACH,
		.checker = amd_cynara_simple_checker,
		.data = PRIVILEGE_PLATFORM
	},
};

static int __on_app_status_cleanup(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int pid;
	uid_t uid;
	amd_app_status_h status = arg3;

	if (status == NULL)
		return -1;

	pid = amd_app_status_get_pid(status);
	uid = amd_app_status_get_uid(status);

	__app_group_remove_full(_app_group_find(pid), uid);
	__app_group_remove_from_recycle_bin(pid);

	return 0;
}

static int __on_status_update(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	bool force = arg1;
	bool update_group_info = arg2;
	amd_app_status_h app_status = arg3;
	app_group_h app_group;
	int status;

	status = amd_app_status_get_status(app_status);
	if (update_group_info && status != STATUS_DYING) {
		app_group = _app_group_find(amd_app_status_get_pid(app_status));
		__app_group_set_status(app_group, status, force);
	}

	return 0;
}

static int __on_term_app(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int pid = arg1;
	amd_request_h req = arg3;
	int *pids = NULL;
	int i;
	int cnt = 0;
	uid_t uid = amd_request_get_target_uid(req);

	if (__app_group_is_leader(_app_group_find(pid))) {
		_app_group_get_group_pids(pid, &cnt, &pids);
		for (i = cnt - 1; i >= 0; i--) {
			if (i != 0)
				amd_launch_term_sub_app(pids[i], uid);
			__app_group_remove(_app_group_find(pids[i]));
		}
		free(pids);
	}

	return 0;
}

static int __on_term_bgapp(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int pid = arg1;
	amd_request_h req = arg3;
	int *pids = NULL;
	int i;
	int cnt = 0;
	int status = -1;
	amd_app_status_h app_status;
	uid_t uid = amd_request_get_target_uid(req);
	app_group_h app_group;

	if (__app_group_is_leader(_app_group_find(pid))) {
		_app_group_get_group_pids(pid, &cnt, &pids);
		if (cnt > 0) {
			app_status = amd_app_status_find_by_pid(pids[cnt - 1]);
			status = amd_app_status_get_status(app_status);
			if (status == STATUS_BG) {
				for (i = cnt - 1 ; i >= 0; i--) {
					if (i != 0)
						amd_launch_term_sub_app(pids[i], uid);
					app_group = _app_group_find(pids[i]);
					__app_group_remove(app_group);
				}
			}
		}
		free(pids);
	}

	return 0;
}

static int __on_app_register_pid(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int pid = arg1;
	amd_appinfo_h ai = arg3;
	bundle *kb = data;
	const char *component_type;

	component_type = amd_appinfo_get_value(ai, AMD_AIT_COMPTYPE);
	if (component_type && strcmp(component_type, APP_TYPE_UI) == 0) {
		__app_group_start_app(pid, kb, pid, FALSE,
				APP_GROUP_LAUNCH_MODE_SINGLE);
	}

	return 0;
}

static int __on_launch_complete(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int pid = arg1;
	amd_appinfo_h ai = arg3;
	bundle *kb = data;
	const char *comp_type;
	bool new_process = arg2;

	comp_type = amd_appinfo_get_value(ai, AMD_AIT_COMPTYPE);
	if (comp_type && !strcmp(comp_type, APP_TYPE_UI)) {
		if (new_process) {
			LOGI("Add app group info %d", pid);
			__app_group_start_app(pid, kb, __launch_context.lpid,
					__launch_context.can_attach,
					__launch_context.mode);
		} else {
			__app_group_restart_app(_app_group_find(pid), kb);
		}
	}

	return 0;
}

static int __on_launch_prepare_ui_start(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int status = arg1;
	uid_t uid = arg2;
	amd_launch_context_h h = arg3;
	bundle *kb = data;
	int pid;
	const char *appid = amd_launch_context_get_appid(h);
	bool can_attach = false;
	int lpid = -1;
	app_group_launch_mode mode = APP_GROUP_LAUNCH_MODE_SINGLE;
	int ret;

	if (__app_group_is_group_app(kb, uid)) {
		amd_launch_context_set_pid(h, -1);
		amd_launch_context_set_subapp(h, true);
		amd_launch_context_set_app_status(h, NULL);
	} else {
		if (amd_launch_context_is_new_instance(h))
			amd_launch_context_set_subapp(h, true);
		else
			amd_launch_context_set_subapp(h, false);
	}

	pid = amd_launch_context_get_pid(h);
	if (pid <= 0 || status == STATUS_DYING) {
		ret = __app_group_can_start_app(appid, kb, &can_attach,
				&lpid, &mode, uid);
		if (ret != 0) {
			LOGE("can't make group info");
			return -1;
		}

		if (can_attach && lpid == -1) {
			LOGE("can't launch singleton app in the same group");
			return -1;
		}
	}

	if (pid == -1 && can_attach) {
		pid = __app_group_find_pid_from_recycle_bin(appid);
		amd_launch_context_set_pid(h, pid);
	}

	return 0;
}

static void __terminate_unmanageable_app(amd_app_status_h app_status)
{
	const char *appid = NULL;
	int cnt = 0;
	int *pids = NULL;
	int i;
	const char *taskmanage = NULL;
	amd_appinfo_h ai = NULL;
	bool bg_allowed;
	amd_app_status_h status_h;
	int st;
	uid_t uid;

	if (!amd_app_status_is_home_app(app_status))
		return;

	__app_group_get_leader_pids(&cnt, &pids);
	if (pids == NULL)
		return;

	for (i = 0; i < cnt; i++) {
		status_h = amd_app_status_find_by_pid(pids[i]);
		if (!status_h)
			continue;

		if (amd_app_status_is_home_app(status_h))
			continue;

		appid = amd_app_status_get_appid(status_h);
		ai = amd_appinfo_find(amd_app_status_get_uid(status_h), appid);
		taskmanage = amd_appinfo_get_value(ai, AMD_AIT_TASKMANAGE);
		bg_allowed = amd_suspend_is_allowed_background(ai);
		uid = amd_app_status_get_uid(status_h);

		if (taskmanage && strcmp("false", taskmanage) == 0
			&& bg_allowed == false) {
			st = amd_app_status_get_status(status_h);
			if (st == STATUS_BG) {
				LOGW("terminate %d %s %d", pids[i], appid, st);
				aul_send_app_terminate_request_signal(pids[i],
						NULL, NULL, NULL);
				amd_launch_term_sub_app(pids[i], uid);
			}
		}
	}

	free(pids);
}

static void _wl_cb_conformant(void *data,
		struct tizen_policy *tizen_policy,
		struct wl_surface *surface_resource,
		uint32_t is_conformant)
{
	; // nothing to do.
}

static void _wl_cb_conformant_area(void *data,
		struct tizen_policy *tizen_policy,
		struct wl_surface *surface_resource,
		uint32_t conformant_part,
		uint32_t state,
		int32_t x, int32_t y, int32_t w, int32_t h)
{
	; // nothing to do.
}

static void _wl_cb_notification_done(void *data,
		struct tizen_policy *tizen_policy,
		struct wl_surface *surface,
		int32_t level,
		uint32_t state)
{
	; // nothing to do.
}

static void _wl_cb_transient_for_done(void *data,
		struct tizen_policy *tizen_policy,
		uint32_t child_id)
{
	; // nothing to do.
}

static void _wl_cb_scr_mode_done(void *data,
		struct tizen_policy *tizen_policy,
		struct wl_surface *surface,
		uint32_t mode,
		uint32_t state)
{
	; // nothing to do.
}

static void _wl_cb_iconify_state_changed(void *data,
		struct tizen_policy *tizen_policy,
		struct wl_surface *surface_resource,
		uint32_t iconified,
		uint32_t force)
{
	; // nothing to do.
}

static void _wl_cb_supported_aux_hints(void *data,
		struct tizen_policy *tizen_policy,
		struct wl_surface *surface_resource,
		struct wl_array *hints,
		uint32_t num_hints)
{
	; // nothing to do.
}

static void _wl_cb_allowed_aux_hint(void *data,
		struct tizen_policy *tizen_policy,
		struct wl_surface *surface_resource,
		int id)
{
	; // nothing to do.
}

static void _wl_cb_aux_message(void *data,
		struct tizen_policy *tizen_policy,
		struct wl_surface *surface_resource,
		const char *key,
		const char *val,
		struct wl_array *options)
{
	; // nothing to do.
}

static void _wl_cb_conformant_region(void *data,
		struct tizen_policy *tizen_policy,
		struct wl_surface *surface,
		uint32_t conformant_part,
		uint32_t state,
		int32_t x, int32_t y, int32_t w, int32_t h,
		uint32_t serial)
{
	; // nothing to do.
}

static const struct tizen_policy_listener _tizen_policy_listener = {
	_wl_cb_conformant,
	_wl_cb_conformant_area,
	_wl_cb_notification_done,
	_wl_cb_transient_for_done,
	_wl_cb_scr_mode_done,
	_wl_cb_iconify_state_changed,
	_wl_cb_supported_aux_hints,
	_wl_cb_allowed_aux_hint,
	_wl_cb_aux_message,
	_wl_cb_conformant_region,
};

static int __on_launch_status_fg(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	amd_app_status_h app_status = arg3;

	if (TIZEN_FEATURE_TERMINATE_UNMANAGEABLE_APP)
		__terminate_unmanageable_app(app_status);

	return 0;
}

static int __on_app_status_add(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	amd_app_status_h app_status = arg3;
	int app_type = amd_app_status_get_app_type(app_status);
	int pid;
	int leader_pid;
	app_group_h app_group;

	if (app_type == AMD_AT_UI_APP) {
		pid = amd_app_status_get_pid(app_status);
		app_group = _app_group_find(pid);
		leader_pid = _app_group_get_leader_pid(app_group);
		amd_app_status_set_leader_pid(app_status, leader_pid);
	}

	return 0;
}

static gint __compare_app_status_for_sorting(gconstpointer p1, gconstpointer p2)
{
	amd_app_status_h app_status1 = (amd_app_status_h)p1;
	amd_app_status_h app_status2 = (amd_app_status_h)p2;
	int app_group_cnt1;
	int app_group_cnt2;
	int *app_group_pids1;
	int *app_group_pids2;
	int fg_cnt1;
	int fg_cnt2;
	int timestamp1;
	int timestamp2;

	if (amd_app_status_get_app_type(app_status1) != AMD_AT_UI_APP ||
			amd_app_status_get_app_type(app_status2) != AMD_AT_UI_APP)
		return 0;

	timestamp1 = amd_app_status_get_timestamp(app_status1);
	timestamp2 = amd_app_status_get_timestamp(app_status2);
	if (timestamp1 > timestamp2)
		return 1;
	else if (timestamp1 < timestamp2)
		return -1;

	_app_group_get_group_pids(amd_app_status_get_leader_pid(app_status1),
			&app_group_cnt1, &app_group_pids1);
	_app_group_get_group_pids(amd_app_status_get_leader_pid(app_status2),
			&app_group_cnt2, &app_group_pids2);
	free(app_group_pids1);
	free(app_group_pids2);

	if (app_group_cnt1 < app_group_cnt2)
		return 1;
	else if (app_group_cnt1 > app_group_cnt2)
		return -1;

	fg_cnt1 = amd_app_status_get_fg_cnt(app_status1);
	fg_cnt2 = amd_app_status_get_fg_cnt(app_status2);
	if (fg_cnt1 > fg_cnt2)
		return 1;
	else if (fg_cnt1 < fg_cnt2)
		return -1;

	return 0;
}

static int __on_app_status_term_bg_apps(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	amd_app_status_term_bg_apps(__compare_app_status_for_sorting);

	return 0;
}

static int __on_wl_listener(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	uint32_t id = (uint32_t)arg1;
	struct wl_registry *reg = (struct wl_registry *)arg3;

	if (!tz_policy) {
		tz_policy_id = id;
		tz_policy = wl_registry_bind(reg, id,
				&tizen_policy_interface, 7);
		amd_wayland_set_tizen_policy(tz_policy);
		if (tz_policy) {
			tizen_policy_add_listener(tz_policy, &_tizen_policy_listener, display);
		}
		LOGD("tz_policy(%p)", tz_policy);
	}

	return 0;
}

static int __on_wl_listener_remove(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	uint32_t id = (uint32_t)arg1;

	if (id == tz_policy_id && tz_policy) {
		tizen_policy_destroy(tz_policy);
		tz_policy = NULL;
		tz_policy_id = 0;
		tz_policy_initialized = 0;
		amd_wayland_set_tizen_policy(tz_policy);
		LOGW("tizen policy is destroyed");
	}

	return 0;
}

int _app_group_init(void)
{
	int r;

	LOGD("app group init");
	app_group_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
			NULL, NULL);
	if (app_group_hash == NULL) {
		LOGE("Failed to create app group hash");
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

	amd_noti_listen("wayland.listener.tizen_policy", __on_wl_listener);
	amd_noti_listen("wayland.listener_remove", __on_wl_listener_remove);
	amd_noti_listen("app_status.cleanup", __on_app_status_cleanup);
	amd_noti_listen("app_status.update_status.end", __on_status_update);
	amd_noti_listen("launch.term_app.start", __on_term_app);
	amd_noti_listen("launch.term_bgapp.start", __on_term_bgapp);
	amd_noti_listen("app_status.app_register_pid", __on_app_register_pid);
	amd_noti_listen("launch.complete.start", __on_launch_complete);
	amd_noti_listen("launch.prepare.ui.start", __on_launch_prepare_ui_start);
	amd_noti_listen("launch.status.fg", __on_launch_status_fg);
	amd_noti_listen("app_status.add", __on_app_status_add);
	amd_noti_listen("app_status.term_bg_apps", __on_app_status_term_bg_apps);

	return 0;
}

void _app_group_fini(void)
{
	LOGD("app group fini");
	/* TODO: Destroy app group info */
}
