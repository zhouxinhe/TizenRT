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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <mntent.h>
#include <glib.h>
#include <gio/gio.h>
#include <systemd/sd-login.h>
#include <tzplatform_config.h>
#include <bundle_internal.h>
#include <aul.h>
#include <aul_sock.h>

#include "amd_util.h"
#include "amd_login_monitor.h"
#include "amd_appinfo.h"
#include "amd_app_property.h"
#include "amd_app_status.h"
#include "amd_socket.h"
#include "amd_request.h"
#include "amd_launch.h"
#include "amd_signal.h"
#include "amd_cynara.h"
#include "amd_noti.h"

#define PATH_AUL_DAEMONS "/run/aul/daemons"
#define LOGIN_TIMEOUT_SEC 90

typedef int (*login_cb)(uid_t uid);
typedef void (*logout_cb)(uid_t uid);

typedef struct login_handler_s {
	uid_state state;
	login_cb login;
} login_handler;

typedef struct logout_handler_s {
	uid_state state;
	logout_cb logout;
} logout_handler;

struct login_monitor_s {
	sd_login_monitor *m;
	GIOChannel *io;
	guint sid;
};

struct user_s {
	uid_t uid;
	uid_state state;
	guint timer;
	guint app_counter_timer;
	GList *app_counter_list;
	pid_t launchpad_pid;
};

struct app_counter_s {
	char *app_type;
	int number[AT_WATCH_APP + 1];
};

static guint sid;
static struct login_monitor_s *login_monitor;
static GList *user_list;
static login_handler login_table[] = {
	{
		.state = UID_STATE_OPENING | UID_STATE_ONLINE |
			UID_STATE_ACTIVE,
		.login = _appinfo_load
	},
	{
		.state = UID_STATE_OPENING | UID_STATE_ONLINE |
			UID_STATE_ACTIVE,
		.login = _app_property_load
	},
	{
		.state = UID_STATE_OPENING | UID_STATE_ONLINE |
			UID_STATE_ACTIVE,
		.login = _app_status_usr_init
	},
	{
		.state = UID_STATE_ONLINE | UID_STATE_ACTIVE,
		.login = _request_usr_init
	},
	{
		.state = UID_STATE_ACTIVE,
		.login = _launch_start_onboot_apps
	}
};
static logout_handler logout_table[] = {
	{
		.state = UID_STATE_OFFLINE,
		.logout = _appinfo_unload
	},
	{
		.state = UID_STATE_OFFLINE,
		.logout = _app_property_unload
	},
	{
		.state = UID_STATE_CLOSING | UID_STATE_OFFLINE,
		.logout = _app_status_usr_fini
	}
};

static int __connect_to_launchpad(uid_t uid);
static void __user_login(struct user_s *user);
static struct user_s *__find_user(uid_t uid);

pid_t _login_monitor_get_launchpad_pid(uid_t uid)
{
	struct user_s *user;

	if (uid < REGULAR_UID_MIN)
		return -1;

	user = __find_user(uid);
	if (!user)
		return -1;

	return user->launchpad_pid;
}

static void __set_launchpad_pid(uid_t uid, pid_t pid)
{
	struct user_s *user;

	if (uid < REGULAR_UID_MIN)
		return;

	user = __find_user(uid);
	if (!user)
		return;

	if (user->launchpad_pid == pid)
		return;

	user->launchpad_pid = pid;
	SECURE_LOGD("User(%u), Launchpad pid(%d)", uid, pid);
}

static void __destroy_app_counter(gpointer data)
{
	struct app_counter_s *ac = (struct app_counter_s *)data;

	if (!ac) {
		_E("Critical error!");
		return;
	}

	free(ac->app_type);
	free(ac);
}

static struct app_counter_s *__create_app_counter(const char *app_type)
{
	struct app_counter_s *ac;

	ac = (struct app_counter_s *)calloc(1, sizeof(struct app_counter_s));
	if (!ac) {
		_E("Out of memory");
		return NULL;
	}

	ac->app_type = strdup(app_type);
	if (!ac->app_type) {
		_E("Out of memory");
		free(ac);
		return NULL;
	}

	return ac;
}

static void __reset_app_counter(gpointer data, gpointer user_data)
{
	struct app_counter_s *ac = (struct app_counter_s *)data;
	int i;

	if (!ac)
		return;

	for (i = 0; i <= AT_WATCH_APP; ++i)
		ac->number[i] = 0;
}

static int __update_app_type_info(const char *app_type, int total, uid_t uid)
{
	bundle *b;
	int r;

	b = bundle_create();
	if (!b) {
		_E("Out of memory");
		return -1;
	}

	r = bundle_add(b, AUL_K_APP_TYPE, app_type);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add app type(%s)", app_type);
		bundle_free(b);
		return -1;
	}

	r = bundle_add(b, AUL_K_IS_INSTALLED, total > 0 ? "true" : "false");
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add install info");
		bundle_free(b);
		return -1;
	}

	r = _send_cmd_to_launchpad_async(LAUNCHPAD_PROCESS_POOL_SOCK, uid,
			PAD_CMD_UPDATE_APP_TYPE, b);
	bundle_free(b);

	return r;
}

static void __foreach_app_counter(gpointer data, gpointer user_data)
{
	struct app_counter_s *ac = (struct app_counter_s *)data;
	struct user_s *user = (struct user_s *)user_data;
	int total;
	int r;

	total = ac->number[AT_UI_APP] + ac->number[AT_WIDGET_APP] +
		ac->number[AT_WATCH_APP];

	r = __update_app_type_info(ac->app_type, total, user->uid);
	if (r < 0)
		_W("Failed to update app type info");

	_D("app type(%s), total(%d)", ac->app_type, total);
}

static struct app_counter_s *__find_app_counter(GList *list,
		const char *app_type)
{
	struct app_counter_s *ac;
	GList *iter;

	iter = g_list_first(list);
	while (iter) {
		ac = (struct app_counter_s *)iter->data;
		if (ac && ac->app_type && !strcmp(ac->app_type, app_type))
			return ac;

		iter = g_list_next(iter);
	}

	return NULL;
}

static int __convert_to_component_type(const char *str)
{
	if (!str)
		return -1;

	if (!strcmp(str, APP_TYPE_SERVICE))
		return AT_SERVICE_APP;
	else if (!strcmp(str, APP_TYPE_UI))
		return AT_UI_APP;
	else if (!strcmp(str, APP_TYPE_WIDGET))
		return AT_WIDGET_APP;
	else if (!strcmp(str, APP_TYPE_WATCH))
		return AT_WATCH_APP;

	return -1;
}

static void __foreach_appinfo(void *data, const char *appid, struct appinfo *ai)
{
	struct user_s *user = (struct user_s *)data;
	struct app_counter_s *ac;
	const char *app_type;
	const char *str;
	int enable = 0;
	int component_type;

	_appinfo_get_int_value(ai, AIT_ENABLEMENT, &enable);
	if (!(enable & APP_ENABLEMENT_MASK_ACTIVE)) {
		return;
	}

	app_type = _appinfo_get_value(ai, AIT_APPTYPE);
	ac = __find_app_counter(user->app_counter_list, app_type);
	if (!ac) {
		ac = __create_app_counter(app_type);
		if (!ac)
			return;

		user->app_counter_list = g_list_append(
				user->app_counter_list, ac);
	}

	str = _appinfo_get_value(ai, AIT_COMPTYPE);
	component_type = __convert_to_component_type(str);
	if (component_type < 0) {
		_W("Error! component type(%s)", str);
		return;
	}

	ac->number[component_type]++;
}

static gboolean __app_counter_cb(gpointer data)
{
	struct user_s *user = (struct user_s *)data;

	if (user->app_counter_list) {
		g_list_foreach(user->app_counter_list,
				__reset_app_counter, user);
	}

	_appinfo_foreach(user->uid, __foreach_appinfo, user);

	if ((user->state & (UID_STATE_ONLINE | UID_STATE_ACTIVE))) {
		g_list_foreach(user->app_counter_list,
				__foreach_app_counter, user);
	}

	user->app_counter_timer = 0;
	return G_SOURCE_REMOVE;
}

static int __on_appinfo_handler(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	uid_t uid = (uid_t)arg1;
	struct user_s *user;
	GList *iter;

	_D("message(%s), uid(%u)", msg, uid);
	iter = user_list;
	while (iter) {
		user = (struct user_s *)iter->data;
		iter = g_list_next(iter);
		if (uid >= REGULAR_UID_MIN && uid != user->uid)
			continue;

		if (user->app_counter_timer)
			g_source_remove(user->app_counter_timer);

		user->app_counter_timer = g_timeout_add(500,
				__app_counter_cb, user);
	}

	return 0;
}

static void __destroy_user(gpointer data)
{
	struct user_s *user = (struct user_s *)data;

	if (!user) {
		_E("Critical error!");
		return;
	}

	if (user->app_counter_list)
		g_list_free_full(user->app_counter_list, __destroy_app_counter);

	if (user->app_counter_timer)
		g_source_remove(user->app_counter_timer);

	if (user->timer)
		g_source_remove(user->timer);

	free(user);
}

static struct user_s *__create_user(uid_t uid)
{
	struct user_s *user;

	user = (struct user_s *)calloc(1, sizeof(struct user_s));
	if (!user) {
		_E("Out of memory");
		return NULL;
	}

	user->uid = uid;
	user->state = UID_STATE_OPENING;

	return user;
}

static struct user_s *__find_user(uid_t uid)
{
	struct user_s *user;
	GList *iter;

	iter = user_list;
	while (iter) {
		user = (struct user_s *)iter->data;
		if (user && user->uid == uid)
			return user;

		iter = g_list_next(iter);
	}

	return NULL;
}

static bool __is_mounted(const char *dir)
{
	struct mntent *ent;
	FILE *fp;
	bool is_mounted = false;

	if (!dir)
		return false;

	fp = setmntent("/etc/mtab", "r");
	if (!fp) {
		_E("Failed to open /etc/mtab");
		return false;
	}

	ent = getmntent(fp);
	while (ent) {
		if (!strcmp(dir, ent->mnt_dir)) {
			is_mounted = true;
			break;
		}

		ent = getmntent(fp);
	}

	endmntent(fp);

	return is_mounted;
}

static gboolean __login_timout_handler(gpointer data)
{
	struct user_s *user = (struct user_s *)data;

	if (user->state == UID_STATE_ACTIVE) {
		_W("User(%u) is already active state", user->uid);
		user->timer = 0;
		return G_SOURCE_REMOVE;
	}

	if (!__is_mounted("/opt/usr")) {
		_W("/opt/usr is not mounted");
		return G_SOURCE_CONTINUE;
	}

	user->timer = 0;
	user->state = UID_STATE_ACTIVE;
	__user_login(user);

	return G_SOURCE_REMOVE;
}

static void __user_login(struct user_s *user)
{
	unsigned int i;

	if (user->state == UID_STATE_OPENING) {
		if (__connect_to_launchpad(user->uid) == 0) {
			user->state = UID_STATE_ONLINE;
			user->timer = g_timeout_add_seconds(
					LOGIN_TIMEOUT_SEC,
					__login_timout_handler,
					user);
		}
	}

	if (user->state == UID_STATE_ONLINE) {
		if (user->app_counter_list) {
			g_list_foreach(user->app_counter_list,
					__foreach_app_counter, user);
		}
	}

	_W("[__LOGIN_MONITOR__] user login - uid(%d), state(%d)",
			user->uid, user->state);
	for (i = 0; i < ARRAY_SIZE(login_table); i++) {
		if (login_table[i].state & user->state) {
			if (login_table[i].login)
				login_table[i].login(user->uid);
		}
	}

	_noti_send("login_monitor.login", user->uid, user->state, NULL, NULL);
}

static void __user_logout(struct user_s *user)
{
	unsigned int i;

	_D("user logout - uid(%d), state(%d)", user->uid, user->state);
	for (i = 0; i < ARRAY_SIZE(logout_table); i++) {
		if (logout_table[i].state & user->state) {
			if (logout_table[i].logout)
				logout_table[i].logout(user->uid);
		}
	}

	_noti_send("login_monitor.logout", user->uid, user->state, NULL, NULL);
}

void _login_monitor_set_uid_state(uid_t uid, uid_state state)
{
	struct user_s *user;

	if (uid < REGULAR_UID_MIN)
		return;

	user = __find_user(uid);
	if (!user)
		return;

	if (user->state != state) {
		user->state = state;
		if (user->state == UID_STATE_ONLINE) {
			user->timer = g_timeout_add_seconds(
					LOGIN_TIMEOUT_SEC,
					__login_timout_handler,
					user);
			__user_login(user);
		} else {
			__user_logout(user);
		}
	}
}

uid_state _login_monitor_get_uid_state(uid_t uid)
{
	uid_state res = UID_STATE_UNKNOWN;
	struct user_s *user;

	if (uid < REGULAR_UID_MIN)
		return res;

	user = __find_user(uid);
	if (!user)
		return res;

	return user->state;
}

int _login_monitor_get_uids(uid_t **uids)
{
	int r;
	uid_t *l;
	GList *iter;
	unsigned int i = 0;
	struct user_s *user;

	if (uids == NULL) {
		_E("Invalid parameter");
		return -1;
	}

	if (user_list == NULL)
		return -1;

	r = g_list_length(user_list);
	if (r == 0)
		return 0;

	l = calloc(r, sizeof(uid_t));
	if (l == NULL) {
		_E("out of memory");
		return -1;
	}

	iter = g_list_first(user_list);
	while (iter) {
		user = (struct user_s *)iter->data;
		l[i++] = user->uid;
		iter = g_list_next(iter);
	}

	*uids = l;

	return r;
}

static int __connect_to_launchpad(uid_t uid)
{
	int r;
	bundle *b;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%d/%s",
			PATH_AUL_DAEMONS, uid, LAUNCHPAD_PROCESS_POOL_SOCK);
	if (access(path, F_OK) != 0) {
		_D("%s doesn't exist", path);
		return -1;
	}

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return -1;
	}

	r = _send_cmd_to_launchpad(LAUNCHPAD_PROCESS_POOL_SOCK,
			uid, PAD_CMD_PING, b);
	bundle_free(b);
	if (r < 0) {
		_E("Failed to connect launchpad - uid(%d), result(%d)", uid, r);
		return -1;
	}

	__set_launchpad_pid(uid, r);

	return 0;
}

static void __check_user_state(void)
{
	uid_t *uids = NULL;
	int ret;
	int i;
	char *state = NULL;
	struct user_s *user;

	ret = sd_get_uids(&uids);
	if (ret <= 0) {
		_W("Failed to get uids - %d", ret);
		return;
	}

	for (i = 0; i < ret; i++) {
		if (uids[i] < REGULAR_UID_MIN)
			continue;

		if (sd_uid_get_state(uids[i], &state) < 0)
			continue;

		user = __find_user(uids[i]);

		if (strcmp(state, "opening") == 0 ||
				strcmp(state, "online") == 0) {
			if (!user) {
				user = __create_user(uids[i]);
				if (!user) {
					free(uids);
					return;
				}
				user_list = g_list_append(user_list, user);
				__user_login(user);
			}
		} else if (strcmp(state, "closing") == 0) {
			if (user) {
				user->state = UID_STATE_CLOSING;
				__user_logout(user);
			}
		} else if (strcmp(state, "offline") == 0) {
			if (user) {
				user_list = g_list_remove(user_list,
						user);
				user->state = UID_STATE_OFFLINE;
				__user_logout(user);
				__destroy_user(user);
			}
		}
		_D("uid(%d), state(%s)", uids[i], state);
		free(state);
		state = NULL;
	}
	free(uids);
}

static gboolean __monitor_login_cb(GIOChannel *io, GIOCondition condition,
		gpointer data)
{
	_D("login monitor");
	sd_login_monitor_flush(login_monitor->m);

	__check_user_state();

	return TRUE;
}

static int __init_login_monitor(void)
{
	int r;
	int fd;

	login_monitor = (struct login_monitor_s *)calloc(1,
			sizeof(struct login_monitor_s));
	if (login_monitor == NULL) {
		_E("out of memory");
		return -1;
	}

	r = sd_login_monitor_new("uid", &login_monitor->m);
	if (r < 0) {
		_E("Failed to create sd login monitor");
		return -1;
	}

	fd = sd_login_monitor_get_fd(login_monitor->m);
	if (fd < 0) {
		_E("Failed to get file descriptor");
		return -1;
	}

	login_monitor->io = g_io_channel_unix_new(fd);
	if (login_monitor->io == NULL) {
		_E("Failed to create GIOChannel");
		return -1;
	}

	login_monitor->sid = g_io_add_watch(login_monitor->io,
			G_IO_IN | G_IO_HUP, __monitor_login_cb, NULL);
	if (login_monitor->sid == 0) {
		_E("Failed to add gio watch");
		return -1;
	}

	return 0;
}

static void __fini_login_monitor(void)
{
	if (login_monitor == NULL)
		return;

	if (login_monitor->sid) {
		g_source_remove(login_monitor->sid);
		login_monitor->sid = 0;
	}

	if (login_monitor->io) {
		g_io_channel_unref(login_monitor->io);
		login_monitor->io = NULL;
	}

	if (login_monitor->m) {
		sd_login_monitor_unref(login_monitor->m);
		login_monitor->m = NULL;
	}

	free(login_monitor);
	login_monitor = NULL;
}

static int __on_startup_finished(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	uid_t uid = (uid_t)arg1;
	struct user_s *user;

	_W("uid(%d)", uid);
	if (uid < REGULAR_UID_MIN)
		return -1;

	user = __find_user(uid);
	if (!user) {
		user = __create_user(uid);
		if (!user)
			return -1;

		user_list = g_list_append(user_list, user);
	} else {
		if (user->state == UID_STATE_ACTIVE) {
			_W("The user(%u) is already active state.", uid);
			return 0;
		}
	}

	if (user->timer) {
		g_source_remove(user->timer);
		user->timer = 0;
	}

	user->state = UID_STATE_ACTIVE;
	__user_login(user);

	return 0;
}

static int __startup_finished_cb(uid_t uid, void *user_data)
{
	_noti_send("startup.finished", (int)uid, 0, user_data, NULL);

	return 0;
}

static int __subscribe_startup_finished(void *data)
{
	return _signal_subscribe_startup_finished(__startup_finished_cb, data);
}

static int __dispatch_app_add_loader(request_h req)
{
	bundle *kb;
	int ret;
	char tmpbuf[MAX_PID_STR_BUFSZ];

	kb = _request_get_bundle(req);
	if (kb == NULL)
		return -1;

	snprintf(tmpbuf, sizeof(tmpbuf), "%d", getpgid(_request_get_pid(req)));
	bundle_add(kb, AUL_K_CALLER_PID, tmpbuf);
	ret = _send_cmd_to_launchpad(LAUNCHPAD_PROCESS_POOL_SOCK,
			_request_get_target_uid(req), PAD_CMD_ADD_LOADER, kb);
	_request_send_result(req, ret);

	return ret;
}

static int __dispatch_app_remove_loader(request_h req)
{
	bundle *kb;
	int ret;

	kb = _request_get_bundle(req);
	if (kb == NULL)
		return -1;

	ret = _send_cmd_to_launchpad(LAUNCHPAD_PROCESS_POOL_SOCK,
			_request_get_target_uid(req), PAD_CMD_REMOVE_LOADER,
			kb);
	_request_send_result(req, ret);

	return ret;
}

static int __dispatch_launchpad_dead_signal(request_h req)
{
	uid_t target_uid = _request_get_target_uid(req);
	pid_t pid = _request_get_pid(req);

	_W("uid(%d), pid(%d)", target_uid, pid);
	_login_monitor_set_uid_state(target_uid, UID_STATE_CLOSING);
	__set_launchpad_pid(target_uid, 0);
	close(_request_remove_fd(req));

	return 0;
}

static int __dispatch_app_prepare_candidate_process(request_h req)
{
	bundle *b = NULL;
	int ret;

	b = bundle_create();
	if (b == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	ret = _send_cmd_to_launchpad(LAUNCHPAD_PROCESS_POOL_SOCK,
			_request_get_target_uid(req), PAD_CMD_DEMAND, b);
	bundle_free(b);

	_request_send_result(req, ret);
	return 0;
}

static int __dispatch_launchpad_launch_signal(request_h req)
{
	uid_t target_uid = _request_get_target_uid(req);
	pid_t pid = _request_get_pid(req);

	_D("uid(%d), pid(%d)", target_uid, pid);
	_login_monitor_set_uid_state(target_uid, UID_STATE_ONLINE);
	__set_launchpad_pid(target_uid, pid);
	close(_request_remove_fd(req));

	return 0;
}

static int __label_checker(caller_info_h info, request_h req,
		void *data)
{
	if (strcmp(_cynara_caller_info_get_client(info), "System::Privileged") == 0)
		return 0;

	return -1;
}

static request_cmd_dispatch __dispatch_table[] = {
	{
		.cmd = APP_ADD_LOADER,
		.callback = __dispatch_app_add_loader
	},
	{
		.cmd = APP_REMOVE_LOADER,
		.callback = __dispatch_app_remove_loader
	},
	{
		.cmd = LAUNCHPAD_DEAD_SIGNAL,
		.callback = __dispatch_launchpad_dead_signal
	},
	{
		.cmd = APP_PREPARE_CANDIDATE_PROCESS,
		.callback = __dispatch_app_prepare_candidate_process
	},
	{
		.cmd = LAUNCHPAD_LAUNCH_SIGNAL,
		.callback = __dispatch_launchpad_launch_signal
	},

};

static cynara_checker __cynara_checkers[] = {
	{
		.cmd = LAUNCHPAD_LAUNCH_SIGNAL,
		.checker = __label_checker,
		.data = NULL
	},
	{
		.cmd = LAUNCHPAD_DEAD_SIGNAL,
		.checker = __label_checker,
		.data = NULL
	},
	{
		.cmd = APP_ADD_LOADER,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_PLATFORM
	},
	{
		.cmd = APP_REMOVE_LOADER,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_PLATFORM
	},
};

static gboolean __login_default_user(gpointer data)
{
	struct user_s *user;
	uid_t uid;

	__check_user_state();

	uid = tzplatform_getuid(TZ_SYS_DEFAULT_USER);
	_W("default user(%d)", uid);

	user = __find_user(uid);
	if (!user) {
		_E("Failed to find default user info");
		return G_SOURCE_REMOVE;
	}

	if (user->state == UID_STATE_UNKNOWN)
		user->state = UID_STATE_OPENING;

	__user_login(user);
	sid = 0;
	return G_SOURCE_REMOVE;
}

int _login_monitor_init(void)
{
	int r;
	uid_t uid;
	struct user_s *user;

	_D("login monitor init");
	if (__init_login_monitor()) {
		_E("Failed to initialize login monitor");
		__fini_login_monitor();
		return -1;
	}

	_noti_listen("startup.finished", __on_startup_finished);
	_noti_listen("appinfo.load", __on_appinfo_handler);
	_noti_listen("appinfo.unload", __on_appinfo_handler);
	_noti_listen("appinfo.reload", __on_appinfo_handler);
	_noti_listen("appinfo.package.install.end", __on_appinfo_handler);
	_noti_listen("appinfo.package.uninstall.end", __on_appinfo_handler);
	_noti_listen("appinfo.package.update.end", __on_appinfo_handler);
	_noti_listen("appinfo.app.enabled.end", __on_appinfo_handler);
	_noti_listen("appinfo.app.disabled.end", __on_appinfo_handler);

	uid = tzplatform_getuid(TZ_SYS_DEFAULT_USER);
	_D("default user(%d)", uid);
	user = __create_user(uid);
	if (!user)
		return -1;

	user_list = g_list_append(user_list, user);
	sid = g_idle_add_full(G_PRIORITY_HIGH, __login_default_user,
			NULL, NULL);

	if (__subscribe_startup_finished(NULL) < 0)
		_signal_add_initializer(__subscribe_startup_finished, NULL);

	r = _request_register_cmds(__dispatch_table,
			ARRAY_SIZE(__dispatch_table));
	if (r < 0) {
		_E("Failed to register cmds");
		return -1;
	}

	r = _cynara_register_checkers(__cynara_checkers,
			ARRAY_SIZE(__cynara_checkers));
	if (r < 0) {
		_E("Failed to register checkers");
		return -1;
	}

	return 0;
}

void _login_monitor_fini(void)
{
	_D("login monitor fini");

	if (sid)
		g_source_remove(sid);

	_signal_unsubscribe_startup_finished();

	if (user_list)
		g_list_free_full(user_list, __destroy_user);

	__fini_login_monitor();
}
