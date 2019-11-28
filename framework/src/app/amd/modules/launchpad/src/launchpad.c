/*
 * Copyright (c) 2017 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <stdbool.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/smack.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/limits.h>
#include <glib.h>
#include <gio/gio.h>
#include <systemd/sd-journal.h>
#include <amd.h>
#include <bundle_internal.h>
#include <security-manager.h>
#include <tzplatform_config.h>
#include <trust-anchor.h>

#include "launchpad-private.h"
#include "launcher_info.h"

#define AUL_K_EXEC			"__AUL_EXEC__"
#define AUL_K_APPID			"__AUL_APPID__"
#define AUL_K_STARTTIME			"__AUL_STARTTIME__"
#define AUL_K_HWACC			"__AUL_HWACC__"
#define AUL_K_TASKMANAGE		"__AUL_TASKMANAGE__"
#define AUL_K_PKGID			"__AUL_PKGID_"
#define AUL_K_PID			"__AUL_PID__"
#define AUL_K_ROOT_PATH			"__AUL_ROOT_PATH__"
#define AUL_K_API_VERSION		"__AUL_API_VERSION__"
#define AUL_K_APP_TYPE			"__AUL_APP_TYPE__"
#define AUL_K_IS_GLOBAL                 "__AUL_IS_GLOBAL__"

#define FORMAT_DBUS_ADDRESS \
	"kernel:path=/sys/fs/kdbus/%u-user/bus;unix:path=/run/user/%u/bus"
#define AUL_DBUS_PATH			"/aul/dbus_handler"
#define AUL_DBUS_INTERFACE		"org.tizen.aul.signal"
#define AUL_DBUS_APP_LAUNCH_SIGNAL	"app_launch"
#define AUL_DBUS_APP_DEAD_SIGNAL	"app_dead"

#define ARG_PATH			0
#define PATH_DEV_NULL			"/dev/null"
#define PATH_AMD_SOCK			"/run/aul/daemons/.amd-sock"
#define APP_STARTUP_SIGNAL		89
#define CONNECT_RETRY_COUNT		3
#define CONNECT_RETRY_TIME		(100 * 1000)

#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

typedef struct _app_pkt_t {
	int cmd;
	int len;
	int opt;
	unsigned char data[1];
} app_pkt_t;

struct launch_arg {
	const char *appid;
	const char *app_path;
	const char *pkgid;
	const char *app_type;
	const char *is_global;
	bundle *b;
};

struct env_map {
	const char *key;
	const char *name;
};

struct app_arg {
	int argc;
	char **argv;
};

static struct env_map env_maps[] = {
	{ AUL_K_STARTTIME, "APP_START_TIME" },
	{ AUL_K_HWACC, "HWACC" },
	{ AUL_K_TASKMANAGE, "TASKMANAGE" },
	{ AUL_K_APPID, "AUL_APPID" },
	{ AUL_K_PKGID, "AUL_PKGID" },
	{ AUL_K_APP_TYPE, "RUNTIME_TYPE" },
	{ AUL_K_API_VERSION, "TIZEN_API_VERSION" },
	{ NULL, NULL },
};

static sigset_t old_mask;
static guint sigchld_sid;
static GDBusConnection *conn;
static GList *launcher_info_list;

static int __unlink_socket_path(int pid, uid_t uid);

static int __send_signal(const char *path, const char *interface,
		const char *signal, GVariant *param)
{
	GError *err = NULL;

	if (!conn) {
		conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (!conn) {
			LOGE("Failed to get system bus - %s", err->message);
			g_error_free(err);
			return -1;
		}
	}

	if (!g_dbus_connection_emit_signal(conn, NULL, path, interface,
				signal, param, &err)) {
		LOGE("Failed to emit signal(%s) - %s", signal, err->message);
		g_error_free(err);
		return -1;
	}

	if (!g_dbus_connection_flush_sync(conn, NULL, &err)) {
		LOGE("Failed to flush connection - %s", err->message);
		g_error_free(err);
		return -1;
	}

	return 0;
}

static void __send_app_launch_signal(int pid, const char *appid)
{
	GVariant *param;
	int r;

	param = g_variant_new("(us)", pid, appid);
	if (!param) {
		LOGE("Out of memory");
		return;
	}

	r = __send_signal(AUL_DBUS_PATH, AUL_DBUS_INTERFACE,
			AUL_DBUS_APP_LAUNCH_SIGNAL, param);
	if (r < 0)
		return;

	LOGD("Send app launch signal - pid(%d), appid(%s)", pid, appid);
}

static void __send_app_dead_signal(int pid)
{
	GVariant *param;
	int r;

	param = g_variant_new("(u)", pid);
	if (!param) {
		LOGE("Out of memory");
		return;
	}

	r = __send_signal(AUL_DBUS_PATH, AUL_DBUS_INTERFACE,
			AUL_DBUS_APP_DEAD_SIGNAL, param);
	if (r < 0)
		return;

	LOGD("Send app dead signal - pid(%d)", pid);
}

static void __init_signal(void)
{
	int i;

	for (i = 0; i < _NSIG; ++i) {
		switch (i) {
		case SIGQUIT:
		case SIGILL:
		case SIGABRT:
		case SIGBUS:
		case SIGFPE:
		case SIGSEGV:
		case SIGPIPE:
			break;
		default:
			signal(i, SIG_DFL);
			break;
		}
	}
}

static void __finish_signal(void)
{
	int i;

	for (i = 0; i < _NSIG; ++i)
		signal(i, SIG_DFL);
}

static int __unblock_sigchld(void)
{
	if (sigprocmask(SIG_SETMASK, &old_mask, NULL) < 0) {
		LOGE("Failed to change blocked signal");
		return -1;
	}

	LOGD("Unblock SIGCHLD");
	return 0;
}

static void __process_sigchld(struct signalfd_siginfo *siginfo)
{
	int status;
	pid_t child_pid;
	pid_t child_pgid;

	child_pgid = getpgid(siginfo->ssi_pid);
	LOGD("pid(%d), pgid(%d), signo(%d), status(%d)",
			siginfo->ssi_pid, child_pgid, siginfo->ssi_signo,
			siginfo->ssi_status);

	while ((child_pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (child_pid == child_pgid)
			killpg(child_pgid, SIGKILL);

		__send_app_dead_signal(child_pid);
		__unlink_socket_path(child_pid, siginfo->ssi_uid);
	}
}

static gboolean __handle_sigchld(GIOChannel *io, GIOCondition cond,
		gpointer data)
{
	struct signalfd_siginfo siginfo;
	ssize_t s;
	int fd = g_io_channel_unix_get_fd(io);
	amd_app_status_h app_status;
	const char *appid;

	do {
		s = read(fd, &siginfo, sizeof(struct signalfd_siginfo));
		if (s == 0)
			break;

		if (s != sizeof(struct signalfd_siginfo))
			break;

		__process_sigchld(&siginfo);
		app_status = amd_app_status_find_by_pid(siginfo.ssi_pid);
		if (app_status) {
			appid = amd_app_status_get_appid(app_status);
			security_manager_cleanup_app(appid, siginfo.ssi_uid, siginfo.ssi_pid);
		}
	} while (s > 0);

	return G_SOURCE_CONTINUE;
}

static void __destroy_func(gpointer data)
{
	GIOChannel *io = (GIOChannel *)data;
	gint fd;

	if (!io)
		return;

	fd = g_io_channel_unix_get_fd(io);
	if (fd > 0)
		close(fd);

	g_io_channel_unref(io);
}

static int __init_sigchld_fd(void)
{
	int fd;
	sigset_t mask;
	GIOChannel *io;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, &old_mask) < 0)
		LOGE("Failed to change blocked signals");

	fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (fd < 0) {
		LOGE("Failed to create signalfd for SIGCHLD");
		return -1;
	}

	io = g_io_channel_unix_new(fd);
	if (!io) {
		LOGE("Failed to create g io channel");
		close(fd);
		return 0;
	}

	sigchld_sid = g_io_add_watch_full(io, G_PRIORITY_DEFAULT, G_IO_IN,
			__handle_sigchld, io, __destroy_func);
	if (sigchld_sid == 0) {
		LOGE("Failed to add sigchld fd wacher");
		g_io_channel_unref(io);
		close(fd);
		return -1;
	}

	return 0;
}

static void __set_user_group(void)
{
	uid_t uid = tzplatform_getuid(TZ_SYS_DEFAULT_USER);
	gid_t gid = tzplatform_getgid(TZ_SYS_DEFAULT_USER);
	const char *user;
	int r;

	user = tzplatform_getenv(TZ_SYS_DEFAULT_USER);
	if (!user) {
		LOGE("Failed to get env - TZ_SYS_DEFAULT_USER");
		return;
	}

	r = initgroups(user, gid);
	if (r != 0)
		LOGE("Failed to initialize the supplementary group access list");

	r = setregid(gid, gid);
	if (r != 0)
		LOGE("Failed to set real and effective group id");

	r = setreuid(uid, uid);
	if (r != 0)
		LOGE("Failed to set real and effective user id");

	tzplatform_set_user(uid);
}

static void __unlink_dir(const char *path)
{
	DIR *dp;
	struct dirent *dentry = NULL;
	struct stat statbuf;
	char buf[PATH_MAX];
	int r;

	dp = opendir(path);
	if (!dp)
		return;

	while ((dentry = readdir(dp)) != NULL) {
		if (!strcmp(dentry->d_name, ".") ||
				!strcmp(dentry->d_name, ".."))
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", path, dentry->d_name);
		r = stat(buf, &statbuf);
		if (r == 0) {
			if (S_ISDIR(statbuf.st_mode))
				__unlink_dir(buf);
			else
				unlink(buf);
		}
	}

	rmdir(path);
	closedir(dp);
}

static int __unlink_socket_path(int pid, uid_t uid)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/run/aul/apps/%d/%d", uid, pid);
	if (access(path, F_OK) == 0)
		__unlink_dir(path);

	if (access(path, F_OK) == 0)
		return -1;

	return 0;
}

static void __redirect_stdio(const char *ident)
{
	int fd;

	/* stdin */
	fd = open(PATH_DEV_NULL, O_RDONLY | O_NOCTTY);
	if (fd < 0) {
		LOGW("Failed to open /dev/null - err(%d)", errno);
		return;
	}
	if (dup2(fd, STDIN_FILENO) < 0) {
		LOGW("Failed to duplicate fd - oldfd(%d), newfd(%d)",
				fd, STDIN_FILENO);
	}
	close(fd);

	/* stdout */
	fd = sd_journal_stream_fd(ident, LOG_INFO, false);
	if (fd < 0) {
		LOGW("Failed to connect journal socket - err(%d)", errno);
		fd = open(PATH_DEV_NULL, O_WRONLY | O_NOCTTY);
		if (fd < 0) {
			LOGW("Failed to open /dev/null - err(%d)", errno);
			return;
		}
	}
	if (dup2(fd, STDOUT_FILENO) < 0) {
		LOGW("Failed to duplicate fd - oldfd(%d), newfd(%d)",
				fd, STDOUT_FILENO);
	}
	close(fd);

	/* stderr */
	fd = sd_journal_stream_fd(ident, LOG_INFO, false);
	if (fd < 0) {
		LOGW("Failed to connect journal socket - err(%d)", errno);
		fd = open(PATH_DEV_NULL, O_WRONLY | O_NOCTTY);
		if (fd < 0) {
			LOGW("Failed to open /dev/null - err(%d)", errno);
			return;
		}
	}

	if (dup2(fd, STDERR_FILENO) < 0) {
		LOGW("Failed to duplicate fd - oldfd(%d), newfd(%d)",
				fd, STDERR_FILENO);
	}
	close(fd);
}

static void __set_env(bundle *b)
{
	const char *val;
	char buf[PATH_MAX];
	int i;

	for (i = 0; env_maps[i].key; ++i) {
		val = bundle_get_val(b, env_maps[i].key);
		if (val)
			setenv(env_maps[i].name, val, 1);
	}

	val = bundle_get_val(b, AUL_K_ROOT_PATH);
	if (val) {
		setenv("AUL_ROOT_PATH", val, 1);
		/* for backward compatibility */
		snprintf(buf, sizeof(buf), "%s/lib/", val);
		setenv("LD_LIBRARY_PATH", buf, 1);
	}

	val = tzplatform_getenv(TZ_USER_HOME);
	if (val)
		setenv("HOME", val, 1);

	val = tzplatform_getenv(TZ_SYS_DEFAULT_USER);
	if (val) {
		setenv("LOGNAME", val, 1);
		setenv("USER", val, 1);
	}

	snprintf(buf, sizeof(buf), "%d", getpid());
	setenv("AUL_PID", buf, 1);

	snprintf(buf, sizeof(buf), "/run/user/%d", getuid());
	setenv("XDG_RUNTIME_DIR", buf, 1);

	snprintf(buf, sizeof(buf), FORMAT_DBUS_ADDRESS, getuid(), getuid());
	setenv("DBUS_SESSION_BUS_ADDRESS", buf, 1);
}

static int __send_cmd_to_amd(int cmd)
{
	struct sockaddr_un addr = {0,};
	int retry = CONNECT_RETRY_COUNT;
	app_pkt_t pkt = {0,};
	int fd;
	int ret;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	/*  support above version 2.6.27*/
	if (fd < 0) {
		if (errno == EINVAL) {
			fd = socket(AF_UNIX, SOCK_STREAM, 0);
			if (fd < 0) {
				LOGE("second chance - socket create error");
				return -1;
			}
		} else {
			LOGE("socket error");
			return -1;
		}
	}

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", PATH_AMD_SOCK);
	while (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		if (errno != ETIMEDOUT || retry <= 0) {
			LOGE("Failed to connect error(%d)", errno);
			close(fd);
			return -1;
		}

		usleep(CONNECT_RETRY_TIME);
		--retry;
		LOGD("re-connect to %s (%d)", addr.sun_path, retry);
	}

	pkt.cmd = cmd;
	ret = send(fd, &pkt, sizeof(app_pkt_t), MSG_NOSIGNAL);
	if (ret <= 0) {
		LOGE("Failed to send cmd(%d), errno(%d)", cmd, errno);
		close(fd);
		return -ECOMM;
	}
	close(fd);

	return 0;
}

static int __prepare_exec(struct launch_arg *arg)
{
	char *name;
	int r;

	/* Set new session ID & new process group ID*/
	/* In linux, child can set new session ID without check permission */
	setsid();

	LOGW("trust_anchor_launch ++");
	if (arg->is_global && !strcmp(arg->is_global, "true"))
		r = trust_anchor_launch(arg->pkgid, GLOBAL_USER);
	else
		r = trust_anchor_launch(arg->pkgid, getuid());
	LOGW("trust_anchor_launch --");
	if (r != TRUST_ANCHOR_ERROR_NONE &&
			r != TRUST_ANCHOR_ERROR_NOT_INSTALLED) {
		LOGE("trust_anchor_launch() is failed. %d", r);
		return -1;
	}

	/* Set privileges */
	LOGW("security_manager_prepare_app ++");
	r = security_manager_prepare_app(arg->appid);
	LOGW("security_manager_prepare_app --");
	if (r != SECURITY_MANAGER_SUCCESS) {
		LOGE("Failed to set privileges");
		return -1;
	}

	__send_cmd_to_amd(APP_STARTUP_SIGNAL);

	name = basename(arg->app_path);
	if (!name) {
		LOGE("Failed to parse name");
		return -1;
	}

	__redirect_stdio(name);
	prctl(PR_SET_NAME, name);
	__set_env(arg->b);

	return 0;
}

static void __close_all_fds(void)
{
	DIR *dp;
	struct dirent *dentry = NULL;
	int fd;
	int max_fd = sysconf(_SC_OPEN_MAX);

	dp = opendir("/proc/self/fd");
	if (!dp) {
		for (fd = 3; fd < max_fd; ++fd)
			close(fd);
		return;
	}

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		fd = atoi(dentry->d_name);
		if (fd < 3 || fd >= max_fd)
			continue;

		if (fd == dirfd(dp))
			continue;

		close(fd);
	}
	closedir(dp);
}

static int __create_launcher_argv(int *argc, char ***argv, const char *app_type)
{
	int launcher_argc;
	char **launcher_argv;
	launcher_info_h launcher_info;
	const char *exe;
	const char *extra_arg;
	GList *extra_args;
	GList *iter;
	int i;

	launcher_info = _launcher_info_find(launcher_info_list, app_type);
	if (launcher_info == NULL)
		return 0;

	exe = _launcher_info_get_exe(launcher_info);
	if (exe == NULL) {
		LOGE("Failed to get launcher exe");
		return -1;
	}

	extra_args = _launcher_info_get_extra_args(launcher_info);
	launcher_argc = g_list_length(extra_args) + 1;
	launcher_argv = (char **)calloc(launcher_argc, sizeof(char *));
	if (launcher_argv == NULL) {
		LOGE("Out of memory");
		return -1;
	}

	i = ARG_PATH;
	launcher_argv[i++] = strdup(exe);

	iter = g_list_first(extra_args);
	while (iter) {
		extra_arg = (const char *)iter->data;
		if (extra_arg)
			launcher_argv[i++] = strdup(extra_arg);

		iter = g_list_next(iter);
	}

	*argc = launcher_argc;
	*argv = launcher_argv;

	return 0;
}

static void __destroy_launcher_argv(int argc, char **argv)
{
	int i;

	if (argv == NULL)
		return;

	for (i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);
}

static int __create_app_argv(int *argc, char ***argv, const char *app_path,
		bundle *b, const char *app_type)
{
	int new_argc;
	char **new_argv;
	struct app_arg launcher_arg = { 0, };
	struct app_arg arg = { 0, };
	int i;
	int r;
	int c;

	r = __create_launcher_argv(&launcher_arg.argc, &launcher_arg.argv,
			app_type);
	if (r < 0) {
		LOGE("Failed to create launcher argv");
		return -1;
	}

	arg.argc = bundle_export_to_argv(b, &arg.argv);
	if (arg.argc <= 0) {
		LOGE("Failed to export bundle");
		__destroy_launcher_argv(launcher_arg.argc, launcher_arg.argv);
		return -1;
	}

	arg.argv[ARG_PATH] = strdup(app_path);
	if (arg.argv[ARG_PATH] == NULL) {
		LOGE("Failed to duplicate app path");
		bundle_free_exported_argv(arg.argc, &arg.argv);
		__destroy_launcher_argv(launcher_arg.argc, launcher_arg.argv);
		return -1;
	}

	new_argc = launcher_arg.argc + arg.argc;
	if (new_argc == arg.argc) {
		*argc = arg.argc;
		*argv = arg.argv;
		return 0;
	}

	new_argv = (char **)calloc(new_argc + 1, sizeof(char *));
	if (new_argv == NULL) {
		LOGE("Out of memory");
		free(arg.argv[ARG_PATH]);
		bundle_free_exported_argv(arg.argc, &arg.argv);
		__destroy_launcher_argv(launcher_arg.argc, launcher_arg.argv);
		return -1;
	}

	c = ARG_PATH;
	for (i = 0; i < launcher_arg.argc; i++)
		new_argv[c++] = launcher_arg.argv[i];
	for (i = 0; i < arg.argc; i++)
		new_argv[c++] = arg.argv[i];

	*argc = new_argc;
	*argv = new_argv;

	return 0;
}

static int __exec_app_process(struct launch_arg *arg)
{
	int app_argc;
	char **app_argv = NULL;
	int i;
	int r;

	__unblock_sigchld();
	__finish_signal();
	__set_user_group();

	LOGD("appid(%s), pid(%d), uid(%d)", arg->appid, getpid(), getuid());

	r = __unlink_socket_path(getpid(), getuid());
	if (r < 0) {
		LOGE("Failed to delete socket path");
		return r;
	}

	r = __prepare_exec(arg);
	if (r < 0) {
		LOGE("Failed to prepare exec");
		return r;
	}

	r = __create_app_argv(&app_argc, &app_argv, arg->app_path, arg->b,
			arg->app_type);
	if (r < 0) {
		LOGE("Failed to create app arg");
		return r;
	}

	for (i = 0; i < app_argc; ++i)
		LOGD("input argument %d: %s##", i, app_argv[i]);

	__close_all_fds();

	r = execv(app_argv[ARG_PATH], app_argv);
	if (r < 0) {
		fprintf(stderr, "Failed to execute %s - err(%d)",
				app_argv[ARG_PATH], errno);
	}

	return r;
}

static int __launcher(bundle *b, uid_t uid, void *user_data)
{
	struct launch_arg arg;
	int pid;
	int r;
	uid_t default_uid = tzplatform_getuid(TZ_SYS_DEFAULT_USER);

	if (!b) {
		LOGE("Invalid parameter");
		return -1;
	}

	if (uid != default_uid) {
		LOGE("uid(%u) is not default uid(%u)", uid, default_uid);
		return -1;
	}

	arg.appid = bundle_get_val(b, AUL_K_APPID);
	arg.app_path = bundle_get_val(b, AUL_K_EXEC);
	arg.pkgid = bundle_get_val(b, AUL_K_PKGID);
	arg.app_type = bundle_get_val(b, AUL_K_APP_TYPE);
	arg.is_global = bundle_get_val(b, AUL_K_IS_GLOBAL);
	arg.b = b;

	pid = fork();
	if (pid == 0) {
		r = __exec_app_process(&arg);
		exit(r);
	} else if (pid > 0) {
		LOGD("==> real launch pid: %d(%s)", pid, arg.app_path);
		__send_app_launch_signal(pid, arg.appid);
	} else {
		LOGE("Failed to fork process");
	}

	return pid;
}

static gboolean __send_startup_finished(gpointer data)
{
	uid_t uid = tzplatform_getuid(TZ_SYS_DEFAULT_USER);

	amd_noti_send("startup.finished", (int)uid, 0, NULL, NULL);
	return G_SOURCE_REMOVE;
}

static void __create_user_directories(void)
{
	char buf[PATH_MAX];
	int pid;

	pid = fork();
	if (pid == 0) {
		__unblock_sigchld();
		__finish_signal();
		__set_user_group();

		snprintf(buf, sizeof(buf), "/run/aul/apps/%u", getuid());
		if (mkdir(buf, 0700) < 0)
			LOGW("Failed to create %s", buf);
		if (smack_setlabel(buf, "User", SMACK_LABEL_ACCESS))
			LOGW("Failed to change smack");

		snprintf(buf, sizeof(buf), "/run/aul/dbspace/%u", getuid());
		if (mkdir(buf, 0701) < 0)
			LOGW("Failed to create %s", buf);
		if (smack_setlabel(buf, "User::Home", SMACK_LABEL_ACCESS))
			LOGW("Failed to change smack");

		exit(EXIT_SUCCESS);
	}
}

EXPORT int AMD_MOD_INIT(void)
{
	int r;

	LOGD("launchpad init");

	r = amd_launchpad_set_launcher(__launcher, NULL);
	if (r < 0)
		return -1;

	r = __init_sigchld_fd();
	if (r < 0)
		return -1;

	__init_signal();
	__create_user_directories();
	launcher_info_list = _launcher_info_load("/usr/share/aul");
	g_idle_add(__send_startup_finished, NULL);

	return 0;
}

EXPORT void AMD_MOD_FINI(void)
{
	LOGD("launchpad fini");

	if (launcher_info_list) {
		_launcher_info_unload(launcher_info_list);
		launcher_info_list = NULL;
	}

	if (conn) {
		g_object_unref(conn);
		conn = NULL;
	}

	if (sigchld_sid > 0) {
		g_source_remove(sigchld_sid);
		sigchld_sid = 0;
	}

	amd_launchpad_set_launcher(NULL, NULL);
}
