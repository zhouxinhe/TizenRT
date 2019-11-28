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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <aul.h>
#include <glib.h>
#include <tzplatform_config.h>
#include <systemd/sd-daemon.h>

#include "amd_util.h"
#include "amd_appinfo.h"
#include "amd_app_status.h"
#include "amd_launch.h"
#include "amd_request.h"
#include "amd_cynara.h"
#include "amd_app_com.h"
#include "amd_socket.h"
#include "amd_signal.h"
#include "amd_suspend.h"
#include "amd_app_property.h"
#include "amd_login_monitor.h"
#include "amd_noti.h"
#include "amd_api.h"
#include "amd_inotify.h"
#include "amd_config.h"

#define AMD_MOD_PATH		"/usr/share/amd/mod"
#define NAME_AMD_MOD_INIT	"AMD_MOD_INIT"
#define NAME_AMD_MOD_FINI	"AMD_MOD_FINI"

typedef int (*amd_mod_init_cb)(void);
typedef void (*amd_mod_fini_cb)(void);

struct restart_info {
	char *appid;
	int count;
	guint timer;
};

static GHashTable *restart_tbl;
static GList *so_handles;
static sigset_t old_mask;

static gboolean __restart_timeout_handler(void *data)
{
	struct restart_info *ri = (struct restart_info *)data;

	_D("ri (%p)", ri);
	_D("appid (%s)", ri->appid);

	g_hash_table_remove(restart_tbl, ri->appid);
	free(ri->appid);
	free(ri);

	return FALSE;
}

static bool __check_restart(const char *appid)
{
	struct restart_info *ri = NULL;
	char err_buf[1024];

	ri = g_hash_table_lookup(restart_tbl, appid);
	if (!ri) {
		ri = calloc(1, sizeof(struct restart_info));
		if (!ri) {
			_E("create restart info: %s",
				strerror_r(errno, err_buf, sizeof(err_buf)));
			return false;
		}
		ri->appid = strdup(appid);
		if (ri->appid == NULL) {
			_E("Out of memory");
			free(ri);
			return false;
		}
		ri->count = 1;
		g_hash_table_insert(restart_tbl, ri->appid, ri);

		_D("ri (%p)", ri);
		_D("appid (%s)", appid);

		ri->timer = g_timeout_add(10 * 1000, __restart_timeout_handler,
				ri);
	} else {
		ri->count++;
		_D("count (%d)", ri->count);
		if (ri->count > 5) {
			g_source_remove(ri->timer);
			g_hash_table_remove(restart_tbl, ri->appid);
			free(ri->appid);
			free(ri);
			return false;
		}
	}
	return true;
}

static bool __can_restart_app(const char *appid, uid_t uid)
{
	const char *pkg_status;
	const char *component_type;
	struct appinfo *ai;
	int r;
	int val = 0;
	int enable = 1;

	_D("appid: %s", appid);
	ai = _appinfo_find(uid, appid);
	if (!ai)
		return false;

	component_type = _appinfo_get_value(ai, AIT_COMPTYPE);
	if (!component_type)
		return false;

	if (strcmp(component_type, APP_TYPE_SERVICE) != 0)
		return false;

	r = _appinfo_get_int_value(ai, AIT_ENABLEMENT, &enable);
	if (r == 0 && !(enable & APP_ENABLEMENT_MASK_ACTIVE)) {
		_D("Disabled");
		return false;
	}

	pkg_status = _appinfo_get_value(ai, AIT_STATUS);
	if (pkg_status && strcmp(pkg_status, "blocking") == 0) {
		_appinfo_set_value(ai, AIT_STATUS, "restart");
	} else if (pkg_status && strcmp(pkg_status, "norestart") == 0) {
		_appinfo_set_value(ai, AIT_STATUS, "installed");
	} else {
		r = _appinfo_get_int_value(ai, AIT_RESTART, &val);
		if (r == 0 && val && __check_restart(appid))
			return true;
	}

	return false;
}

static int __app_dead_handler(int pid, void *data)
{
	bool restart = false;
	char *appid = NULL;
	const char *tmp_appid;
	app_status_h app_status;
	uid_t uid;
	char buf[MAX_LOCAL_BUFSZ];

	if (pid <= 0)
		return 0;

	_W("APP_DEAD_SIGNAL : %d", pid);

	app_status = _app_status_find(pid);
	if (app_status == NULL)
		return 0;

	uid = _app_status_get_uid(app_status);
	_noti_send("main.app_dead", pid, uid, app_status, NULL);
	tmp_appid = _app_status_get_appid(app_status);
	if (tmp_appid == NULL)
		return 0;

	uid = _app_status_get_uid(app_status);
	restart = __can_restart_app(tmp_appid, uid);
	if (restart) {
		appid = strdup(tmp_appid);
		if (appid == NULL)
			_W("Out of memory");
	}

	_request_flush_pending_request(pid);
	_app_status_publish_status(pid, STATUS_TERMINATE);
	_app_status_cleanup(app_status);

	if (restart)
		_launch_start_app_local(uid, appid);
	if (appid)
		free(appid);

	snprintf(buf, sizeof(buf), "%d", pid);
	_util_save_log("TERMINATED", buf);
	return 0;
}

static int __listen_app_dead_signal(void *data)
{
	int ret;

	ret = aul_listen_app_dead_signal(__app_dead_handler, data);
	if (ret < 0)
		return -1;

	return 0;
}

static void __ignore_app_dead_signal(void)
{
	aul_listen_app_dead_signal(NULL, NULL);
}

static int __load_modules(const char *path)
{
	DIR *dp;
	struct dirent *dentry = NULL;
	char buf[PATH_MAX];
	char *ext;
	void *handle;
	amd_mod_init_cb init_cb;

	if (path == NULL)
		return -1;

	dp = opendir(path);
	if (dp == NULL)
		return -1;

	while ((dentry = readdir(dp)) != NULL) {
		if (dentry->d_name[0] == '.')
			continue;

		ext = strrchr(dentry->d_name, '.');
		if (ext && strcmp(ext, ".so") != 0)
			continue;
		snprintf(buf, sizeof(buf), "%s/%s",
				path, dentry->d_name);

		handle = dlopen(buf, RTLD_LAZY | RTLD_GLOBAL);
		if (!handle) {
			_E("Failed to load - %s", dlerror());
			continue;
		}

		init_cb = dlsym(handle, NAME_AMD_MOD_INIT);
		if (!init_cb) {
			_E("Failed to find entry point");
			dlclose(handle);
			continue;
		}

		if (init_cb() < 0) {
			_E("Failed to init %s", dentry->d_name);
			dlclose(handle);
			closedir(dp);
			return -1;
		}

		so_handles = g_list_append(so_handles, handle);
	}
	closedir(dp);

	return 0;
}

static void __unload_modules()
{
	GList *i = so_handles;
	amd_mod_fini_cb fini_cb;

	while (i) {
		fini_cb = dlsym(i->data, NAME_AMD_MOD_FINI);
		if (fini_cb)
			fini_cb();
		else
			_E("Failed to find entry point");

		dlclose(i->data);
		i = g_list_next(i);
	}

	g_list_free(so_handles);
	so_handles = NULL;
}

static void __block_sigchld(void)
{
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, &old_mask) < 0)
		_E("Failed to chagne blocked signal");
}

static void __unblock_sigchld(void)
{
	if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0)
		_E("Failed to change blocked signal");
}

static int __init(void)
{
	int r;

	__block_sigchld();
	_request_init();
	_noti_init();
	if (_appinfo_init()) {
		_E("_appinfo_init failed");
		return -1;
	}

	if (__listen_app_dead_signal(NULL) < 0) {
		_W("aul_listen_app_dead_signal failed");
		_signal_add_initializer(__listen_app_dead_signal, NULL);
	}

	restart_tbl = g_hash_table_new(g_str_hash, g_str_equal);

	r = _cynara_init();
	if (r != 0) {
		_E("cynara initialize failed.");
		return -1;
	}

	_app_status_init();
	_app_com_broker_init();
	_launch_init();
	_suspend_init();
	_signal_init();
	_app_property_init();
	_login_monitor_init();
	_util_init();
	_inotify_init();
	_config_init();

	if (access(AMD_MOD_PATH, F_OK) == 0) {
		if (__load_modules(AMD_MOD_PATH) < 0)
			return -1;
	}

	return 0;
}

static void __ready(void)
{
	int fd;

	_D("AMD is ready");

	fd = creat("/run/.amd_ready",
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (fd != -1)
		close(fd);

	sd_notify(0, "READY=1");
}

static void __finish(void)
{
	__unload_modules();
	_config_fini();
	_inotify_fini();
	_util_fini();
	_login_monitor_fini();
	_app_property_fini();
	_suspend_fini();
	_app_com_broker_fini();
	_app_status_finish();
	_request_fini();
	_cynara_finish();

	if (restart_tbl) {
		g_hash_table_destroy(restart_tbl);
		restart_tbl = NULL;
	}

	__ignore_app_dead_signal();

	_appinfo_fini();
	_noti_fini();
	__unblock_sigchld();
}

EXPORT int main(int argc, char *argv[])
{
	GMainLoop *mainloop = NULL;

	if (__init() != 0) {
		_E("AMD Initialization failed!\n");
		return -1;
	}

	__ready();

	mainloop = g_main_loop_new(NULL, FALSE);
	if (!mainloop) {
		_E("failed to create glib main loop");
		return -1;
	}
	g_main_loop_run(mainloop);

	__finish();

	return 0;
}
