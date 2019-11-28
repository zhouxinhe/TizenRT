/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <glib.h>
// #include <gio/gio.h>
// #include <ttrace.h>

// #include <bundle_internal.h>

#include "app_signal.h"
#include "aul.h"
#include "aul_api.h"
#include "aul_sock.h"
#include "aul_util.h"
#include "launch.h"
#include "key.h"
#include "aul_app_com.h"
#include "aul_error.h"

#define TEP_ISMOUNT_MAX_RETRY_CNT 20

static int aul_initialized = 0;
static int aul_fd;
static void *__window_object = NULL;
static void *__bg_object = NULL;
static void *__conformant_object = NULL;

static void __clear_internal_key(bundle *kb);
static inline void __set_stime(bundle *kb);

int aul_is_initialized()
{
	return aul_initialized;
}

static int __send_cmd_for_uid_opt(int pid, uid_t uid, int cmd, bundle *kb, int opt)
{
	int res;

	res = aul_sock_send_bundle(pid, uid, cmd, kb, opt);
	if (res < 0)
		res = aul_error_convert(res);

	return res;
}

static int __send_cmd_noreply_for_uid_opt(int pid, uid_t uid,
		int cmd, bundle *kb, int opt)
{
	int res;

	res = aul_sock_send_bundle(pid, uid, cmd, kb, opt | AUL_SOCK_NOREPLY);
	if (res < 0)
		res = aul_error_convert(res);

	return res;
}

static int __send_cmd_async_for_uid_opt(int pid, uid_t uid,
		int cmd, bundle *kb, int opt)
{
	int res;

	res = aul_sock_send_bundle(pid, uid, cmd, kb, opt | AUL_SOCK_ASYNC);
	if (res < 0)
		res = aul_error_convert(res);

	return res;
}

/**
 * @brief	encode kb and send it to 'pid'
 * @param[in]	pid		receiver's pid
 * @param[in]	cmd		message's status (APP_START | APP_RESULT)
 * @param[in]	kb		data
 */
API int app_send_cmd(int pid, int cmd, bundle *kb)
{
	return __send_cmd_for_uid_opt(pid, getuid(), cmd, kb, AUL_SOCK_NONE);
}

API int app_send_cmd_for_uid(int pid, uid_t uid, int cmd, bundle *kb)
{
	return __send_cmd_for_uid_opt(pid, uid, cmd, kb, AUL_SOCK_NONE);
}

API int app_send_cmd_with_queue_for_uid(int pid, uid_t uid, int cmd, bundle *kb)
{
	return __send_cmd_for_uid_opt(pid, uid, cmd, kb, AUL_SOCK_QUEUE);
}

API int app_send_cmd_with_queue_noreply_for_uid(int pid, uid_t uid,
					int cmd, bundle *kb)
{
	return __send_cmd_noreply_for_uid_opt(pid, uid, cmd, kb, AUL_SOCK_QUEUE);
}

API int app_send_cmd_with_noreply(int pid, int cmd, bundle *kb)
{
	return __send_cmd_for_uid_opt(pid, getuid(), cmd, kb, AUL_SOCK_NOREPLY);
}

API int app_send_cmd_to_launchpad(const char *pad_type, uid_t uid, int cmd, bundle *kb)
{
	int fd;
	int len;
	int res;
	char buf[1024];

	fd = aul_sock_create_launchpad_client(pad_type, uid);
	if (fd < 0)
		return -1;

	res = aul_sock_send_bundle_with_fd(fd, cmd,
			kb, AUL_SOCK_ASYNC);
	if (res < 0) {
		close(fd);
		return res;
	}

retry_recv:
	len = recv(fd, &res, sizeof(int), 0);
	if (len == -1) {
		if (errno == EAGAIN) {
			_E("recv timeout: %d(%s)",
					errno,
					strerror_r(errno, buf, sizeof(buf)));
			res = -EAGAIN;
		} else if (errno == EINTR) {
			_D("recv: %d(%s)",
					errno,
					strerror_r(errno, buf, sizeof(buf)));
			goto retry_recv;
		} else {
			_E("recv error: %d(%s)",
					errno,
					strerror_r(errno, buf, sizeof(buf)));
			res = -ECOMM;
		}
	}

	close(fd);

	return res;
}

static void __clear_internal_key(bundle *kb)
{
	bundle_del(kb, AUL_K_CALLER_PID);
	bundle_del(kb, AUL_K_APPID);
	bundle_del(kb, AUL_K_WAIT_RESULT);
	bundle_del(kb, AUL_K_SEND_RESULT);
	bundle_del(kb, AUL_K_ARGV0);
}

static inline void __set_stime(bundle *kb)
{
	struct timeval tv;
	char tmp[MAX_LOCAL_BUFSZ];

	gettimeofday(&tv, NULL);
	snprintf(tmp, MAX_LOCAL_BUFSZ, "%ld/%ld", tv.tv_sec, tv.tv_usec);
	bundle_del(kb, AUL_K_STARTTIME);
	bundle_add(kb, AUL_K_STARTTIME, tmp);
}

int app_request_local(int cmd, bundle *kb)
{
	bundle *b;

	_E("app_request_to_launchpad : Same Process Send Local");

	switch (cmd) {
	case APP_START:
	case APP_START_RES:
	case APP_START_ASYNC:
	case WIDGET_UPDATE:
	case APP_START_RES_ASYNC:
	case APP_SEND_LAUNCH_REQUEST:
		b = bundle_dup(kb);
		return aul_launch_local(b);
	case APP_OPEN:
	case APP_RESUME:
	case APP_RESUME_BY_PID:
	case APP_RESUME_BY_PID_ASYNC:
		return aul_resume_local();
	default:
		_E("no support packet");
		return AUL_R_LOCAL;
	}
}

/**
 * @brief	start caller with kb
 * @return	callee's pid
 */
int app_request_to_launchpad(int cmd, const char *appid, bundle *kb)
{
	return app_request_to_launchpad_for_uid(cmd, appid, kb, getuid());
}

int app_request_to_launchpad_for_uid(int cmd, const char *appid, bundle *kb, uid_t uid)
{
	int must_free = 0;
	int ret = 0;
	char buf[MAX_PID_STR_BUFSZ];

	traceBegin(TTRACE_TAG_APPLICATION_MANAGER, "AUL:REQ_TO_PAD");
	_W("request cmd(%d) : appid(%s), target_uid(%d)", cmd, appid, uid);
	if (kb == NULL) {
		kb = bundle_create();
		must_free = 1;
	} else {
		__clear_internal_key(kb);
	}

	bundle_del(kb, AUL_K_APPID);
	bundle_add(kb, AUL_K_APPID, appid);
	__set_stime(kb);
	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_del(kb, AUL_K_TARGET_UID);
	bundle_add(kb, AUL_K_TARGET_UID, buf);

	switch (cmd) {
	case APP_PAUSE:
	case APP_PAUSE_BY_PID:
		ret = app_send_cmd_with_queue_noreply_for_uid(AUL_UTIL_PID,
				uid, cmd, kb);
		break;
	case APP_SEND_LAUNCH_REQUEST:
		ret = __send_cmd_async_for_uid_opt(AUL_UTIL_PID,
				uid, cmd, kb, AUL_SOCK_QUEUE);
		break;
	default:
		ret = app_send_cmd_with_queue_for_uid(AUL_UTIL_PID, uid, cmd,
				kb);
		break;
	}

	_W("request cmd(%d) result : %d", cmd, ret);
	if (ret == AUL_R_LOCAL)
		ret = app_request_local(cmd, kb);

	/* cleanup */
	if (must_free)
		bundle_free(kb);

	traceEnd(TTRACE_TAG_APPLICATION_MANAGER);

	return ret;
}

static int __get_preinit_fd(void)
{
	int fd = -1;
	const char *listen_fd;

	listen_fd = getenv("AUL_LISTEN_FD");
	if (listen_fd) {
		if (isdigit(*listen_fd))
			fd = atoi(listen_fd);
		unsetenv("AUL_LISTEN_FD");
	}

	return fd;
}

int aul_initialize()
{
	int flag;

	if (aul_initialized)
		return AUL_R_ECANCELED;

	aul_fd = __get_preinit_fd();
	if (aul_fd > 0 && aul_fd < sysconf(_SC_OPEN_MAX)) {
		flag = fcntl(aul_fd, F_GETFD);
		flag |= FD_CLOEXEC;
		(void)fcntl(aul_fd, F_SETFD, flag);
	} else {
		_W("Failed to get preinit fd");
		aul_fd = aul_sock_create_server(getpid(), getuid());
		if (aul_fd < 0) {
			_E("aul_init create sock failed");
			return AUL_R_ECOMM;
		}
	}
	aul_notify_start();

	aul_initialized = 1;

	return aul_fd;
}

API void aul_finalize()
{
	aul_launch_fini();

	if (aul_initialized) {
		aul_sock_destroy_server(aul_fd);
		aul_fd = -1;
	}

	return;
}

API int aul_request_data_control_socket_pair(bundle *kb, int *fd)
{
	bundle *b = kb;
	int ret;
	int clifd;
	int fds[2] = { 0, };

	if (!fd)
		return AUL_R_EINVAL;

	if (b) {
		__clear_internal_key(b);
	} else {
		b = bundle_create();
		if (!b)
			return AUL_R_ERROR;
	}

	clifd = aul_sock_send_bundle(AUL_UTIL_PID, getuid(), APP_GET_DC_SOCKET_PAIR, b, AUL_SOCK_ASYNC);
	if (kb == NULL)
		bundle_free(b);

	if (clifd > 0) {
		ret = aul_sock_recv_result_with_fd(clifd);
		if (ret < 0) {
			close(clifd);
			if (ret == -EILLEGALACCESS) {
				_E("Illegal access in datacontrol socket pair request");
				return AUL_R_EILLACC;
			}
			return ret;
		}

		ret = aul_sock_recv_reply_sock_fd(clifd, &fds, 1);
		if (ret == 0)
			fd[0] = fds[0];
	} else {
		return AUL_R_ERROR;
	}

	return ret;
}

API int aul_request_message_port_socket_pair(int *fd)
{
	int ret;
	int fds[2] = {0,};

	if (!fd)
		return AUL_R_EINVAL;

	ret = aul_sock_send_raw(AUL_UTIL_PID, getuid(),
			APP_GET_MP_SOCKET_PAIR, NULL, 0, AUL_SOCK_ASYNC);
	if (ret > 0) {
		ret = aul_sock_recv_reply_sock_fd(ret, &fds, 2);
		if (ret == 0) {
			fd[0] = fds[0];
			fd[1] = fds[1];
		}
	}

	return ret;
}

API int aul_launch_app(const char *appid, bundle *kb)
{
	return aul_launch_app_for_uid(appid, kb, getuid());
}

API int aul_launch_app_for_uid(const char *appid, bundle *kb, uid_t uid)
{
	int ret;

	if (appid == NULL)
		return AUL_R_EINVAL;

	ret = app_request_to_launchpad_for_uid(APP_START, appid, kb, uid);
	return ret;
}

API int aul_open_app(const char *appid)
{
	return aul_open_app_for_uid(appid, getuid());
}

API int aul_open_app_for_uid(const char *appid, uid_t uid)
{
	int ret;

	if (appid == NULL)
		return AUL_R_EINVAL;

	ret = app_request_to_launchpad_for_uid(APP_OPEN, appid, NULL, uid);
	return ret;
}

API int aul_resume_app(const char *appid)
{
	return aul_resume_app_for_uid(appid, getuid());
}

API int aul_resume_app_for_uid(const char *appid, uid_t uid)
{
	int ret;

	if (appid == NULL)
		return AUL_R_EINVAL;

	ret = app_request_to_launchpad_for_uid(APP_RESUME, appid, NULL, uid);
	return ret;
}

API int aul_resume_pid(int pid)
{
	return aul_resume_pid_for_uid(pid, getuid());
}

API int aul_resume_pid_for_uid(int pid, uid_t uid)
{
	char pid_str[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	ret = app_request_to_launchpad_for_uid(APP_RESUME_BY_PID,
			pid_str, NULL, uid);
	return ret;
}

API int aul_terminate_pid(int pid)
{
	return aul_terminate_pid_for_uid(pid, getuid());
}

API int aul_terminate_pid_for_uid(int pid, uid_t uid)
{
	char pid_str[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	ret = app_request_to_launchpad_for_uid(APP_TERM_BY_PID,
			pid_str, NULL, uid);
	if (ret == pid)
		ret = AUL_R_OK;

	return ret;
}

API int aul_terminate_bgapp_pid(int pid)
{
	char pid_str[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	ret = app_request_to_launchpad(APP_TERM_BGAPP_BY_PID, pid_str, NULL);
	if (ret == pid)
		ret = AUL_R_OK;

	return ret;
}

API int aul_terminate_pid_without_restart(int pid)
{
	char pid_str[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	ret = app_request_to_launchpad(APP_TERM_BY_PID_WITHOUT_RESTART,
			pid_str, NULL);
	return ret;
}

API int aul_terminate_pid_sync_without_restart(int pid)
{
	return aul_terminate_pid_sync_without_restart_for_uid(pid, getuid());
}

API int aul_terminate_pid_sync_without_restart_for_uid(int pid, uid_t uid)
{
	char pid_str[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	ret = app_request_to_launchpad_for_uid(APP_TERM_BY_PID_SYNC_WITHOUT_RESTART,
			pid_str, NULL, uid);
	return ret;
}

API int aul_terminate_pid_async(int pid)
{
	return aul_terminate_pid_async_for_uid(pid, getuid());
}

API int aul_terminate_pid_async_for_uid(int pid, uid_t uid)
{
	char pid_str[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	ret = app_request_to_launchpad_for_uid(APP_TERM_BY_PID_ASYNC, pid_str,
			NULL, uid);
	return ret;
}

API int aul_kill_pid(int pid)
{
	char pid_str[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	ret = app_request_to_launchpad(APP_KILL_BY_PID, pid_str, NULL);
	return ret;
}

API void aul_set_preinit_window(void *evas_object)
{
	__window_object = evas_object;
}

API void* aul_get_preinit_window(const char *win_name)
{
	return __window_object;
}

API void aul_set_preinit_background(void *evas_object)
{
	__bg_object = evas_object;
}

API void* aul_get_preinit_background(void)
{
	return __bg_object;
}

API void aul_set_preinit_conformant(void *evas_object)
{
	__conformant_object = evas_object;
}

API void* aul_get_preinit_conformant(void)
{
	return __conformant_object;
}

API int aul_pause_app(const char *appid)
{
	return aul_pause_app_for_uid(appid, getuid());
}

API int aul_pause_app_for_uid(const char *appid, uid_t uid)
{
	int ret;

	if (appid == NULL)
		return AUL_R_EINVAL;

	ret = app_request_to_launchpad_for_uid(APP_PAUSE, appid, NULL, uid);
	return ret;
}

API int aul_pause_pid(int pid)
{
	return aul_pause_pid_for_uid(pid, getuid());
}

API int aul_pause_pid_for_uid(int pid, uid_t uid)
{
	char pid_str[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	ret = app_request_to_launchpad_for_uid(APP_PAUSE_BY_PID,
			pid_str, NULL, uid);
	return ret;
}

API int aul_reload_appinfo(void)
{
	char pid_str[MAX_PID_STR_BUFSZ];

	snprintf(pid_str, sizeof(pid_str), "%d", getpid());

	return app_request_to_launchpad(AMD_RELOAD_APPINFO, pid_str, NULL);
}

API int aul_is_tep_mount_dbus_done(const char *tep_string)
{
	GError *err = NULL;
	GDBusConnection *conn;
	GDBusMessage *msg = NULL;
	GDBusMessage *reply = NULL;
	GVariant *body;
	int ret = AUL_R_ERROR;

	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
	if (conn == NULL) {
		_E("g_bus_get_sync() is failed. %s", err->message);
		g_error_free(err);
		return AUL_R_ERROR;
	}

	msg = g_dbus_message_new_method_call(TEP_BUS_NAME,
					TEP_OBJECT_PATH,
					TEP_INTERFACE_NAME,
					TEP_IS_MOUNTED_METHOD);
	if (msg == NULL) {
		_E("g_dbus_message_new_method_call() is failed. %s",
				err->message);
		goto end;
	}
	g_dbus_message_set_body(msg, g_variant_new("(s)", tep_string));

	reply = g_dbus_connection_send_message_with_reply_sync(conn,
					msg,
					G_DBUS_SEND_MESSAGE_FLAGS_NONE,
					500,
					NULL,
					NULL,
					&err);
	if (reply == NULL) {
		_E("g_dbus_connection_send_message_with_reply_sync() "
					"is failed. %s", err->message);
		goto end;
	}

	body = g_dbus_message_get_body(reply);
	if (body == NULL) {
		_E("g_dbus_message_get_body() is failed.");
		goto end;
	}

	g_variant_get(body, "(i)", &ret);

end:
	if (msg)
		g_object_unref(msg);
	if (reply)
		g_object_unref(reply);
	if (conn)
		g_object_unref(conn);

	g_clear_error(&err);

	return ret;
}

API int aul_check_tep_mount(const char *tep_path)
{
	if (tep_path) {
		int rv = -1;
		int cnt = 0;
		while (cnt < TEP_ISMOUNT_MAX_RETRY_CNT) {
			rv = aul_is_tep_mount_dbus_done(tep_path);
			if (rv == 1)
				break;
			usleep(50 * 1000);
			cnt++;
		}
		/* incase after trying 1 sec, not getting mounted then quit */
		if (rv != 1) {
			_E("Not able to mount within 1 sec");
			return -1;
		}
	}
	return 0;
}

API int aul_add_loader(const char *loader_path, bundle *kb)
{
	return aul_add_loader_for_uid(loader_path, kb, getuid());
}

API int aul_add_loader_for_uid(const char *loader_path, bundle *kb, uid_t uid)
{
	int ret;
	bundle *b;
	bundle_raw *kb_raw = NULL;
	int len;
	char buf[MAX_PID_STR_BUFSZ];

	if (loader_path == NULL)
		return AUL_R_EINVAL;

	b = bundle_create();
	if (b == NULL)
		return AUL_R_ERROR;

	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_add_str(b, AUL_K_TARGET_UID, buf);
	bundle_add_str(b, AUL_K_LOADER_PATH, loader_path);

	if (kb) {
		ret = bundle_encode(kb, &kb_raw, &len);
		if (ret != BUNDLE_ERROR_NONE) {
			bundle_free(b);
			return AUL_R_EINVAL;
		}

		bundle_add_str(b, AUL_K_LOADER_EXTRA, (const char *)kb_raw);
	}

	ret = app_send_cmd_for_uid(AUL_UTIL_PID, uid, APP_ADD_LOADER, b);
	bundle_free(b);
	if (kb_raw)
		free(kb_raw);

	return ret;
}

API int aul_remove_loader(int loader_id)
{
	return aul_remove_loader_for_uid(loader_id, getuid());
}

API int aul_remove_loader_for_uid(int loader_id, uid_t uid)
{
	char buf[MAX_PID_STR_BUFSZ];
	int ret;
	bundle *b;

	if (loader_id <= 0)
		return AUL_R_EINVAL;

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%d", loader_id);
	bundle_add_str(b, AUL_K_LOADER_ID, buf);
	snprintf(buf, sizeof(buf), "%d", uid);
	bundle_add_str(b, AUL_K_TARGET_UID, buf);

	ret = app_send_cmd_for_uid(AUL_UTIL_PID, uid, APP_REMOVE_LOADER, b);
	bundle_free(b);

	return ret;
}

API int aul_app_register_pid(const char *appid, int pid)
{
	char pid_str[MAX_PID_STR_BUFSZ];
	int ret;
	bundle *b;

	if (!appid || pid <= 0)
		return AUL_R_EINVAL;

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	bundle_add_str(b, AUL_K_APPID, appid);
	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	bundle_add_str(b, AUL_K_PID, pid_str);

	ret = app_send_cmd_with_noreply(AUL_UTIL_PID, APP_REGISTER_PID, b);
	bundle_free(b);

	return ret;
}

API int aul_launch_app_async(const char *appid, bundle *kb)
{
	return aul_launch_app_async_for_uid(appid, kb, getuid());
}

API int aul_launch_app_async_for_uid(const char *appid, bundle *kb, uid_t uid)
{
	int ret;

	if (appid == NULL)
		return AUL_R_EINVAL;

	ret = app_request_to_launchpad_for_uid(APP_START_ASYNC, appid, kb, uid);
	return ret;
}

API int aul_prepare_candidate_process(void)
{
	unsigned char dummy[1] = { 0 };

	return aul_sock_send_raw(AUL_UTIL_PID, getuid(),
			APP_PREPARE_CANDIDATE_PROCESS, dummy, 0, AUL_SOCK_NONE);
}

API int aul_terminate_pid_sync(int pid)
{
	return aul_terminate_pid_sync_for_uid(pid, getuid());
}

API int aul_terminate_pid_sync_for_uid(int pid, uid_t uid)
{
	char pid_str[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	ret = app_request_to_launchpad_for_uid(APP_TERM_BY_PID_SYNC, pid_str,
			NULL, uid);
	return ret;
}

API int aul_resume_pid_async(int pid)
{
	return aul_resume_pid_async_for_uid(pid, getuid());
}

API int aul_resume_pid_async_for_uid(int pid, uid_t uid)
{
	char pid_str[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pid_str, sizeof(pid_str), "%d", pid);
	ret = app_request_to_launchpad_for_uid(APP_RESUME_BY_PID_ASYNC,
			pid_str, NULL, uid);
	return ret;
}

API int aul_resume_app_by_instance_id(const char *appid,
		const char *instance_id)
{
	return aul_resume_app_by_instance_id_for_uid(appid,
			instance_id, getuid());
}

API int aul_resume_app_by_instance_id_for_uid(const char *appid,
		const char *instance_id, uid_t uid)
{
	int ret;
	bundle *b;

	if (appid == NULL || instance_id == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	b = bundle_create();
	if (b == NULL) {
		_E("Out of memory");
		return AUL_R_EINVAL;
	}

	ret = bundle_add(b, AUL_K_INSTANCE_ID, instance_id);
	if (ret != BUNDLE_ERROR_NONE) {
		_E("Failed to add instance id(%s)", instance_id);
		bundle_free(b);
		return AUL_R_ERROR;
	}

	ret = app_request_to_launchpad_for_uid(APP_RESUME, appid, b, uid);
	bundle_free(b);

	return ret;
}
