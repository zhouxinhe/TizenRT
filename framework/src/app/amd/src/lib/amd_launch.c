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
#include <stdbool.h>
#include <signal.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <aul.h>
#include <glib.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <pkgmgr-info.h>
#include <poll.h>
#include <tzplatform_config.h>
#include <cert-svc/ccert.h>
#include <cert-svc/cinstance.h>
#include <aul_sock.h>
#include <aul_svc.h>
#include <aul_svc_priv_key.h>
#include <aul_rpc_port.h>
#include <ttrace.h>
#include <app2ext_interface.h>
#include <vconf.h>

#include "amd_launch.h"
#include "amd_appinfo.h"
#include "amd_app_status.h"
#include "amd_util.h"
#include "app_signal.h"
#include "amd_socket.h"
#include "amd_app_com.h"
#include "amd_suspend.h"
#include "amd_signal.h"
#include "amd_app_property.h"
#include "amd_request.h"
#include "amd_noti.h"
#include "amd_cynara.h"
#include "amd_launchpad.h"
#include "amd_config.h"
#include "amd_login_monitor.h"
#include "amd_proc.h"

#define DAC_ACTIVATE

#define TERM_WAIT_SEC 3
#define INIT_PID 1

#define AUL_PR_NAME 16
#define OSP_K_LAUNCH_TYPE "__OSP_LAUNCH_TYPE__"
#define OSP_V_LAUNCH_TYPE_DATACONTROL "datacontrol"
#define PENDING_REQUEST_TIMEOUT 5000 /* msec */
#define SYSTEM_REQUEST_TIMEOUT 90000 /* msec */
#define PENDING_MESSAGE_MAX_CNT 100

#define APPID_WIDGET_VIEWER_SDK	"org.tizen.widget_viewer_sdk"

struct launch_s {
	const char *appid;
	struct appinfo *ai;
	const char *instance_id;
	int pid;
	bool new_process;
	bool is_subapp;
	int prelaunch_attr;
	int bg_category;
	bool bg_allowed;
	bool bg_launch;
	bool new_instance;
	app_status_h app_status;
	bool debug_mode;
};

struct fgmgr {
	guint tid;
	int pid;
};

struct onboot_app_info {
	char *appid;
	uid_t uid;
};

static GList *_fgmgr_list;
static int __pid_of_last_launched_ui_app;
static int __focused_pid;
static GList *__onboot_list;
static int __poweroff_state;
static launch_mode_e __launch_mode = LAUNCH_MODE_NORMAL;

static void __set_reply_handler(int fd, int pid, request_h req, int cmd);
static int __nofork_processing(int cmd, int pid, bundle *kb, request_h req);

static void __poweroff_state_cb(int state, void *user_data)
{
	_W("[__POWEROFF__] state: %d -> %d", __poweroff_state, state);
	__poweroff_state = state;
	if (__poweroff_state == POWEROFF_DIRECT ||
			__poweroff_state == POWEROFF_RESTART) {
		_W("System shutdown");
		__launch_mode = LAUNCH_MODE_BLOCK;
	}
	_noti_send("poweroff.state.change", state, 0, NULL, NULL);
}

static void __set_stime(bundle *kb)
{
	struct timeval tv;
	char tmp[MAX_LOCAL_BUFSZ];

	gettimeofday(&tv, NULL);
	snprintf(tmp, MAX_LOCAL_BUFSZ, "%ld/%ld", tv.tv_sec, tv.tv_usec);
	bundle_add(kb, AUL_K_STARTTIME, tmp);
}

int _launch_start_app_local_with_bundle(uid_t uid, const char *appid,
		bundle *kb)
{
	request_h req;
	int r;
	bool dummy;
	bool dummy_mode;

	__set_stime(kb);
	bundle_add(kb, AUL_K_APPID, appid);
	req = _request_create_local(APP_START, uid, getpid(), kb);
	if (req == NULL) {
		_E("out of memory");
		return -1;
	}

	r = _launch_start_app(appid, req, &dummy, &dummy_mode, false);
	_request_free_local(req);

	return r;
}

int _launch_start_app_local(uid_t uid, const char *appid)
{
	int pid;
	bundle *kb;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return -1;
	}

	pid = _launch_start_app_local_with_bundle(uid, appid, kb);
	bundle_free(kb);

	return pid;
}

static bool __check_onboot_cond(uid_t uid, const char *appid,
		struct appinfo *ai)
{
	app_status_h app_status;
	const char *comp_type;
	const char *onboot;

	comp_type = _appinfo_get_value(ai, AIT_COMPTYPE);
	if (comp_type == NULL || strcmp(comp_type, APP_TYPE_SERVICE) != 0)
		return false;

	onboot = _appinfo_get_value(ai, AIT_ONBOOT);
	if (onboot == NULL || strcmp(onboot, "true") != 0)
		return false;

	app_status = _app_status_find_by_appid(appid, uid);
	if (_app_status_is_running(app_status) > 0)
		return false;

	return true;
}

int _launch_start_onboot_app_local(uid_t uid, const char *appid,
		struct appinfo *ai)
{
	if (appid == NULL || ai == NULL)
		return -1;

	if (!__check_onboot_cond(uid, appid, ai))
		return -1;

	_D("start app %s from user %d by onboot", appid, uid);
	return _launch_start_app_local(uid, appid);
}

int _terminate_app_local(uid_t uid, int pid)
{
	request_h req;
	int ret;

	req = _request_create_local(APP_TERM_BY_PID, uid, getpid(), NULL);
	if (req == NULL) {
		_E("Out of memory");
		return -1;
	}

	aul_send_app_terminate_request_signal(pid, NULL, NULL, NULL);
	ret = _term_app(pid, req);
	_request_free_local(req);

	return ret;
}

static int __send_to_sigkill(int pid, uid_t uid)
{
	int pgid;
	pid_t launchpad_pid;

	if (pid <= 1)
		return -1;

	pgid = getpgid(pid);
	if (pgid <= 1)
		return -1;

	launchpad_pid = _login_monitor_get_launchpad_pid(uid);
	if (launchpad_pid == pgid) {
		SECURE_LOGE("pgid(%d) of pid(%d) is launchpad", pgid, pid);
		if (kill(pid, SIGKILL) < 0) {
			_E("Failed to send SIGKILL to %d", pid);
			return -1;
		}
		return 0;
	}

	_W("Kill Process Group: pid(%d), pgid(%d)", pid, pgid);
	if (killpg(pgid, SIGKILL) < 0)
		return -1;

	return 0;
}

int _resume_app(int pid, request_h req)
{
	int dummy;
	int ret;
	uid_t target_uid = _request_get_target_uid(req);

	ret = aul_sock_send_raw(pid, target_uid,
			APP_RESUME_BY_PID, (unsigned char *)&dummy, 0,
			AUL_SOCK_ASYNC);
	if (ret < 0) {
		if (ret == -EAGAIN) {
			_E("resume packet timeout error");
		} else {
			_E("raise failed - %d resume fail\n", pid);
			_E("we will term the app - %d\n", pid);
			__send_to_sigkill(pid, target_uid);
			ret = -1;
		}
		_request_send_result(req, ret);
	}
	_D("resume done\n");

	if (ret > 0)
		__set_reply_handler(ret, pid, req, APP_RESUME_BY_PID);

	return ret;
}

int _pause_app(int pid, request_h req)
{
	int dummy;
	int ret;
	uid_t target_uid = _request_get_target_uid(req);

	ret = aul_sock_send_raw(pid, target_uid,
			APP_PAUSE_BY_PID, (unsigned char *)&dummy, 0,
			AUL_SOCK_ASYNC);
	if (ret < 0) {
		if (ret == -EAGAIN) {
			_E("pause packet timeout error");
		} else {
			_E("iconify failed - %d pause fail", pid);
			_E("we will term the app - %d", pid);
			__send_to_sigkill(pid, target_uid);
			ret = -1;
		}
		_request_send_result(req, ret);
	}
	_D("pause done");

	if (ret > 0)
		__set_reply_handler(ret, pid, req, APP_PAUSE_BY_PID);

	return ret;
}

int _term_sub_app(int pid, uid_t uid)
{
	int dummy;
	int ret;

	ret = aul_sock_send_raw(pid, uid, APP_TERM_BY_PID_ASYNC,
			(unsigned char *)&dummy, 0, AUL_SOCK_NOREPLY);
	if (ret < 0) {
		_E("terminate packet send error - use SIGKILL pid(%d)", pid);
		if (__send_to_sigkill(pid, uid) < 0) {
			_E("fail to killing - %d\n", pid);
			return -1;
		}
	}

	return 0;
}

int _term_app(int pid, request_h req)
{
	int dummy;
	int ret;
	uid_t uid = _request_get_target_uid(req);

	_noti_send("launch.term_app.start", pid, 0, req, NULL);
	ret = aul_sock_send_raw(pid, uid, APP_TERM_BY_PID,
			(unsigned char *)&dummy, 0, AUL_SOCK_ASYNC);
	if (ret < 0) {
		_E("terminate packet send error - use SIGKILL pid(%d)", pid);
		if (__send_to_sigkill(pid, uid) < 0) {
			_E("fail to killing - %d\n", pid);
			_request_send_result(req, -1);
			return -1;
		}
		_request_send_result(req, 0);
	}
	_D("term done\n");

	if (ret > 0)
		__set_reply_handler(ret, pid, req, APP_TERM_BY_PID);

	return 0;
}

int _term_req_app(int pid, request_h req)
{
	int dummy;
	int ret;

	ret = aul_sock_send_raw(pid, _request_get_target_uid(req),
			APP_TERM_REQ_BY_PID, (unsigned char *)&dummy, 0,
			AUL_SOCK_ASYNC);
	if (ret < 0) {
		_D("terminate req send error");
		_request_send_result(req, ret);
	}

	if (ret > 0)
		__set_reply_handler(ret, pid, req, APP_TERM_REQ_BY_PID);

	return 0;
}

int _term_bgapp(int pid, request_h req)
{
	int dummy;
	int ret;
	uid_t uid = _request_get_target_uid(req);

	_noti_send("launch.term_bgapp.start", pid, 0, req, NULL);
	ret = aul_sock_send_raw(pid, uid, APP_TERM_BGAPP_BY_PID,
			(unsigned char *)&dummy, sizeof(int), AUL_SOCK_ASYNC);
	if (ret < 0) {
		_E("terminate packet send error - use SIGKILL pid(%d)", pid);
		if (__send_to_sigkill(pid, uid) < 0) {
			_E("fail to killing - %d", pid);
			_request_send_result(req, -1);
			return -1;
		}
		_request_send_result(req, 0);
	}
	_D("term_bgapp done");

	if (ret > 0)
		__set_reply_handler(ret, pid, req, APP_TERM_BGAPP_BY_PID);

	return 0;
}

int _term_app_v2(int pid, request_h req, bool *pend)
{
	int dummy;
	int ret;
	uid_t uid = _request_get_target_uid(req);

	_noti_send("launch.term_app.start", pid, 0, req, NULL);
	ret = aul_sock_send_raw(pid, uid, APP_TERM_BY_PID_SYNC,
			(unsigned char *)&dummy, 0,
			AUL_SOCK_ASYNC | AUL_SOCK_NOREPLY);
	if (ret < 0) {
		_E("Failed to send the terminate packet - use SIGKILL pid(%d)",
				pid);
		if (__send_to_sigkill(pid, uid) < 0) {
			_E("Failed to kill - %d\n", pid);
			_request_send_result(req, -1);
			return -1;
		}
	}
	_D("term v2 done");

	if (pend)
		*pend = true;

	return 0;
}

static int __fake_launch_app(int cmd, int pid, bundle *kb, request_h req)
{
	int ret;

	ret = aul_sock_send_bundle(pid, _request_get_target_uid(req), cmd, kb,
			AUL_SOCK_ASYNC);
	if (ret < 0) {
		_E("error request fake launch - error code = %d", ret);
		_request_send_result(req, ret);
	}

	if (ret > 0)
		__set_reply_handler(ret, pid, req, cmd);

	return ret;
}

static int __fake_launch_app_async(int cmd, int pid, bundle *kb, request_h req)
{
	int ret;

	ret = aul_sock_send_bundle(pid, _request_get_target_uid(req), cmd, kb,
			AUL_SOCK_ASYNC);
	if (ret < 0) {
		_E("error request fake launch - error code = %d", ret);
		_request_send_result(req, ret);
	}

	if (ret > 0) {
		_send_result_to_client(_request_remove_fd(req), pid);
		__set_reply_handler(ret, pid, req, cmd);
	}

	return ret;
}

static gboolean __au_glib_check(GSource *src)
{
	GSList *fd_list;
	GPollFD *tmp;

	fd_list = src->poll_fds;
	do {
		tmp = (GPollFD *) fd_list->data;
		if ((tmp->revents & (POLLIN | POLLPRI)))
			return TRUE;
		fd_list = fd_list->next;
	} while (fd_list);

	return FALSE;
}

static gboolean __au_glib_dispatch(GSource *src, GSourceFunc callback,
		gpointer data)
{
	callback(data);
	return TRUE;
}

static gboolean __au_glib_prepare(GSource *src, gint *timeout)
{
	return FALSE;
}

static GSourceFuncs funcs = {
	.prepare = __au_glib_prepare,
	.check = __au_glib_check,
	.dispatch = __au_glib_dispatch,
	.finalize = NULL
};

struct reply_info {
	GSource *src;
	GPollFD *gpollfd;
	guint timer_id;
	int clifd;
	int pid;
	int cmd;
	bundle *kb;
	uid_t uid;
};

static gboolean __reply_handler(gpointer data)
{
	struct reply_info *r_info = (struct reply_info *)data;
	int fd = r_info->gpollfd->fd;
	int len;
	int res = 0;
	int clifd = r_info->clifd;
	int pid = r_info->pid;
	char err_buf[1024];

	len = recv(fd, &res, sizeof(int), 0);
	if (len == -1) {
		if (errno == EAGAIN) {
			_E("recv timeout : %s",
				strerror_r(errno, err_buf, sizeof(err_buf)));
			res = -EAGAIN;
		} else {
			_E("recv error : %s",
				strerror_r(errno, err_buf, sizeof(err_buf)));
			res = -ECOMM;
		}
		if (r_info->cmd == APP_START_ASYNC) {
			_noti_send("launch.recv.error", r_info->pid,
					r_info->uid, NULL, r_info->kb);
		}
	}
	close(fd);

	if (res >= 0)
		res = pid;
	_send_result_to_client(clifd, res);

	_D("listen fd : %d , send fd : %d, pid : %d", fd, clifd, pid);

	g_source_remove(r_info->timer_id);
	g_source_remove_poll(r_info->src, r_info->gpollfd);
	g_source_destroy(r_info->src);
	g_source_unref(r_info->src);
	g_free(r_info->gpollfd);
	if (r_info->kb)
		bundle_free(r_info->kb);
	free(r_info);

	return TRUE;
}

static gboolean __recv_timeout_handler(gpointer data)
{
	struct reply_info *r_info = (struct reply_info *)data;
	int fd = r_info->gpollfd->fd;
	int clifd = r_info->clifd;
	const char *appid;
	const struct appinfo *ai;
	const char *taskmanage;
	app_status_h app_status;
	uid_t uid;
	int ret = -EAGAIN;

	_E("application is not responding: pid(%d) cmd(%d)",
			r_info->pid, r_info->cmd);
	close(fd);

	switch (r_info->cmd) {
	case APP_OPEN:
	case APP_RESUME:
	case APP_START:
	case APP_START_RES:
	case APP_START_ASYNC:
	case APP_START_RES_ASYNC:
	case APP_SEND_LAUNCH_REQUEST:
		app_status = _app_status_find(r_info->pid);
		if (app_status == NULL)
			break;

		uid = _app_status_get_uid(app_status);
		_noti_send("launch.recv.timeout", r_info->pid, uid, NULL,
				r_info->kb);

		appid = _app_status_get_appid(app_status);
		ai = _appinfo_find(uid, appid);
		if (ai == NULL)
			break;
		taskmanage = _appinfo_get_value(ai, AIT_TASKMANAGE);
		if ((_app_status_get_app_type(app_status) == AT_WIDGET_APP) ||
				(taskmanage && strcmp(taskmanage, "true") == 0))
			_signal_send_watchdog(r_info->pid, SIGKILL);
		break;
	case APP_TERM_BY_PID:
	case APP_TERM_BGAPP_BY_PID:
		if (__send_to_sigkill(r_info->pid, r_info->uid) == 0)
			ret = 0;
		break;
	}

	_send_result_to_client(clifd, ret);
	g_source_remove_poll(r_info->src, r_info->gpollfd);
	g_source_destroy(r_info->src);
	g_source_unref(r_info->src);
	g_free(r_info->gpollfd);
	if (r_info->kb)
		bundle_free(r_info->kb);
	free(r_info);

	return FALSE;
}

static void __set_reply_handler(int fd, int pid, request_h req, int cmd)
{
	GPollFD *gpollfd;
	GSource *src;
	struct reply_info *r_info;
	struct timeval tv;
	bundle *kb = _request_get_bundle(req);

	src = g_source_new(&funcs, sizeof(GSource));
	if (src == NULL) {
		_E("Out of memory");
		return;
	}

	gpollfd = (GPollFD *)g_malloc(sizeof(GPollFD));
	if (gpollfd == NULL) {
		_E("Out of memory");
		g_source_unref(src);
		return;
	}

	gpollfd->events = POLLIN;
	gpollfd->fd = fd;

	r_info = malloc(sizeof(*r_info));
	if (r_info == NULL) {
		_E("out of memory");
		g_free(gpollfd);
		g_source_unref(src);
		return;
	}

	if (kb) {
		r_info->kb = bundle_dup(kb);
		if (r_info->kb == NULL) {
			_E("Out of memory");
			free(r_info);
			g_free(gpollfd);
			g_source_unref(src);
			return;
		}
	} else {
		r_info->kb = NULL;
	}

	r_info->clifd = _request_remove_fd(req);
	r_info->pid = pid;
	r_info->src = src;
	r_info->gpollfd = gpollfd;
	r_info->cmd = cmd;
	r_info->uid = _request_get_target_uid(req);

	tv = aul_sock_get_rcv_timeval();
	r_info->timer_id = g_timeout_add_seconds(tv.tv_sec,
			__recv_timeout_handler, (gpointer)r_info);
	g_source_add_poll(src, gpollfd);
	g_source_set_callback(src, (GSourceFunc)__reply_handler,
			(gpointer)r_info, NULL);
	g_source_set_priority(src, G_PRIORITY_DEFAULT);
	g_source_attach(src, NULL);

	_D("listen fd : %d, send fd : %d", fd, r_info->clifd);
}

static int __nofork_processing(int cmd, int pid, bundle *kb, request_h req)
{
	int ret;

	_noti_send("launch.do_starting_app.relaunch.start", cmd, pid, req, kb);

	switch (cmd) {
	case APP_OPEN:
	case APP_RESUME:
		_D("resume app's pid : %d\n", pid);
		ret = _resume_app(pid, req);
		if (ret < 0)
			_E("__resume_app failed. error code = %d", ret);
		_D("resume app done");
		break;
	case APP_START:
	case APP_START_RES:
	case APP_SEND_LAUNCH_REQUEST:
		_D("fake launch pid : %d\n", pid);
		ret = __fake_launch_app(cmd, pid, kb, req);
		if (ret < 0)
			_E("fake_launch failed. error code = %d", ret);
		_D("fake launch done");
		break;
	case APP_START_ASYNC:
	case APP_START_RES_ASYNC:
		ret = __fake_launch_app_async(cmd, pid, kb, req);
		if (ret < 0)
			_E("fake_launch_async failed. error code = %d", ret);
		_D("fake launch async done");
		break;
	default:
		_E("unknown command: %d", cmd);
		ret = -1;
	}

	return ret;
}

static int __compare_signature(const struct appinfo *ai, int cmd,
		uid_t caller_uid, const char *appid, const char *caller_appid)
{
	const char *permission;
	const struct appinfo *caller_ai;
	const char *preload;
	const char *api_version;
	pkgmgrinfo_cert_compare_result_type_e compare_result;

	permission = _appinfo_get_value(ai, AIT_PERM);
	if (permission && strcmp(permission, "signature") == 0) {
		if (caller_uid != 0 && (cmd == APP_START ||
					cmd == APP_START_RES ||
					cmd == APP_START_ASYNC ||
					cmd == APP_START_RES_ASYNC ||
					cmd == APP_SEND_LAUNCH_REQUEST)) {
			caller_ai = _appinfo_find(caller_uid, caller_appid);
			preload = _appinfo_get_value(caller_ai, AIT_PRELOAD);
			if (!preload || strcmp(preload, "true") == 0)
				return 0;

			api_version = _appinfo_get_value(caller_ai,
					AIT_API_VERSION);
			if (api_version && strverscmp(api_version, "2.4") < 0)
				return 0;

			/* is admin is global */
			if (caller_uid != GLOBAL_USER) {
				pkgmgrinfo_pkginfo_compare_usr_app_cert_info(
						caller_appid, appid,
						caller_uid, &compare_result);
			} else {
				pkgmgrinfo_pkginfo_compare_app_cert_info(
						caller_appid, appid,
						&compare_result);
			}

			if (compare_result != PMINFO_CERT_COMPARE_MATCH)
				return -EILLEGALACCESS;
		}
	}

	return 0;
}

static void __prepare_to_suspend(int pid, uid_t uid)
{
	int dummy = 0;

	SECURE_LOGD("[__SUSPEND__] pid: %d, uid: %d", pid, uid);
	aul_sock_send_raw(pid, uid, APP_SUSPEND, (unsigned char *)&dummy,
			sizeof(int), AUL_SOCK_NOREPLY);
}

static void __prepare_to_wake_services(int pid, uid_t uid)
{
	int dummy = 0;

	SECURE_LOGD("[__SUSPEND__] pid: %d, uid: %d", pid, uid);
	aul_sock_send_raw(pid, uid, APP_WAKE, (unsigned char *)&dummy,
			sizeof(int), AUL_SOCK_NOREPLY);
}

static gboolean __check_service_only(gpointer user_data)
{
	int pid = GPOINTER_TO_INT(user_data);
	app_status_h app_status;

	SECURE_LOGD("[__SUSPEND__] pid :%d", pid);
	app_status = _app_status_find(pid);
	_app_status_check_service_only(app_status,
			__prepare_to_suspend);

	return FALSE;
}

static int __check_allowed_appid(const char *callee_appid,
		const char *caller_appid, uid_t uid)
{
	app_property_h app_property;
	GList *list;
	GList *iter;
	char *allowed_appid;

	app_property = _app_property_find(uid);
	if (app_property == NULL)
		return -1;

	list = _app_property_get_allowed_app_list(app_property, callee_appid);
	iter = g_list_first(list);
	while (iter) {
		allowed_appid = (char *)iter->data;
		if (allowed_appid && strcmp(allowed_appid, caller_appid) == 0) {
			_D("allowed appid(%s), appid(%s)",
					allowed_appid, callee_appid);
			return 0;
		}

		iter = g_list_next(iter);
	}

	return -1;
}

static int __check_platform_app(struct appinfo *ai, uid_t uid)
{
	const char *v;
	const char *pkgid;
	int vi_num;
	int visibility;
	char num[256];

	pkgid = _appinfo_get_value(ai, AIT_PKGID);
	if (pkgid == NULL)
		return 0;

	v = _appinfo_get_value(ai, AIT_VISIBILITY);
	if (v == NULL) {
		vi_num = _appinfo_get_cert_visibility(pkgid,
				uid);
		snprintf(num, sizeof(num), "%d", vi_num);
		_appinfo_set_value(ai, AIT_VISIBILITY, num);
		v = num;
	}

	visibility = atoi(v);
	if (visibility & CERTSVC_VISIBILITY_PLATFORM)
		return 1;

	return 0;
}

static int __check_execute_permission(const char *callee_pkgid,
		const char *caller_appid, uid_t caller_uid, request_h req)
{
	bundle *kb = _request_get_bundle(req);
	struct appinfo *ai;
	const char *caller_pkgid;
	const char *launch_type;
	const char *callee_appid = bundle_get_val(kb, AUL_K_APPID);
	const char *req_type;
	int ret;

	if (callee_pkgid == NULL)
		return -1;

	ai = _appinfo_find(caller_uid, caller_appid);
	if (ai == NULL)
		return 0;

	caller_pkgid = _appinfo_get_value(ai, AIT_PKGID);
	if (caller_pkgid == NULL)
		return 0;

	if (strcmp(caller_pkgid, callee_pkgid) == 0)
		return 0;

	ret = __check_allowed_appid(callee_appid, caller_appid, caller_uid);
	if (ret == 0)
		return 0;

	req_type = _request_get_request_type(req);
	if (req_type &&
		(!strcmp(req_type, "rpc-port") ||
		 !strcmp(req_type, "complication")))
		return 0;

	launch_type = bundle_get_val(kb, OSP_K_LAUNCH_TYPE);
	if (launch_type == NULL
		|| strcmp(launch_type, OSP_V_LAUNCH_TYPE_DATACONTROL) != 0) {
		if (!__check_platform_app(ai, caller_uid)) {
			_E("Couldn't launch service app in other packages");
			return -EREJECTED;
		}
	}

	return 0;
}

static gboolean __fg_timeout_handler(gpointer data)
{
	struct fgmgr *fg = data;
	app_status_h app_status;

	if (!fg)
		return FALSE;

	app_status = _app_status_find(fg->pid);
	if (app_status == NULL)
		return FALSE;

	_W("%d is running in the background", fg->pid);
	_app_status_update_status(app_status, STATUS_BG, true, true);

	_fgmgr_list = g_list_remove(_fgmgr_list, fg);
	free(fg);

	return FALSE;
}

static int __launch_add_fgmgr(int pid)
{
	struct fgmgr *fg;

	fg = calloc(1, sizeof(struct fgmgr));
	if (!fg) {
		_E("Out of memory");
		return -1;
	}

	fg->pid = pid;
	fg->tid = g_timeout_add(_config_get_fg_timeout(),
			__fg_timeout_handler, fg);

	_fgmgr_list = g_list_append(_fgmgr_list, fg);

	return 0;
}

static void __launch_remove_fgmgr(int pid)
{
	GList *iter = NULL;
	struct fgmgr *fg;

	if (pid < 0)
		return;

	for (iter = _fgmgr_list; iter != NULL; iter = g_list_next(iter)) {
		fg = (struct fgmgr *)iter->data;
		if (fg->pid == pid) {
			g_source_remove(fg->tid);
			_fgmgr_list = g_list_remove(_fgmgr_list, fg);
			free(fg);
			return;
		}
	}
}

static int __send_hint_for_visibility(uid_t uid)
{
	bundle *b;
	int ret;

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return -1;
	}

	ret = _send_cmd_to_launchpad(LAUNCHPAD_PROCESS_POOL_SOCK, uid,
			PAD_CMD_VISIBILITY, b);
	bundle_free(b);
	__pid_of_last_launched_ui_app = 0;

	return ret;
}

static int __app_status_handler(int pid, int status, void *data)
{
	const char *appid;
	int old_status;
	const struct appinfo *ai;
	app_status_h app_status;
	uid_t uid;

	_W("pid(%d) status(%d)", pid, status);
	app_status = _app_status_find(pid);
	if (app_status == NULL)
		return 0;

	old_status = _app_status_get_status(app_status);
	if (old_status == STATUS_DYING && old_status != PROC_STATUS_LAUNCH)
		return 0;

	uid = _app_status_get_uid(app_status);
	switch (status) {
	case PROC_STATUS_FG:
		__launch_remove_fgmgr(pid);
		_app_status_update_status(app_status, STATUS_VISIBLE, false,
				true);
		_suspend_remove_timer(pid);
		_noti_send("launch.status.fg", pid, uid, app_status, NULL);
		break;
	case PROC_STATUS_BG:
		_app_status_update_status(app_status, STATUS_BG, false, true);
		appid = _app_status_get_appid(app_status);
		ai = _appinfo_find(uid, appid);
		if (!_suspend_is_allowed_background(ai)) {
			__prepare_to_suspend(pid, uid);
			_suspend_add_timer(pid);
		}
		_noti_send("launch.status.bg", pid, uid, app_status, NULL);
		break;
	case PROC_STATUS_FOCUS:
		__focused_pid = pid;
		_noti_send("launch.status.focus", pid, uid, app_status, NULL);
		break;

	case PROC_STATUS_HIDE:
		_app_status_update_status(app_status, STATUS_BG, false, true);
		_noti_send("launch.status.hide", pid, uid, app_status, NULL);
		break;

	case PROC_STATUS_LAUNCH:
		appid = _app_status_get_appid(app_status);
		if (appid)
			LOG(LOG_DEBUG, "LAUNCH", "[%s:Application:Launching:done]", appid);
		if (pid == __pid_of_last_launched_ui_app)
			__send_hint_for_visibility(uid);
		_noti_send("launch.status.launch", pid, uid, app_status, NULL);
		break;

	}

	return 0;
}

void _launch_set_focused_pid(int pid)
{
	__focused_pid = pid;
}

int _launch_get_focused_pid(void)
{
	return __focused_pid;
}

static int __listen_app_status_signal(void *data)
{
	int ret;

	ret = aul_listen_app_status_signal(__app_status_handler, data);
	if (ret < 0)
		return -1;

	return 0;
}

static int __listen_poweroff_state_signal(void *data)
{
	int ret;

	ret = _signal_subscribe_poweroff_state(__poweroff_state_cb, data);
	if (ret < 0)
		return -1;

	return 0;
}

static void __set_effective_appid(uid_t uid, bundle *kb)
{
	const struct appinfo *ai;
	const struct appinfo *effective_ai;
	const char *appid;
	const char *effective_appid;
	const char *pkgid;
	const char *effective_pkgid;

	appid = bundle_get_val(kb, AUL_K_APPID);
	if (appid == NULL)
		return;

	ai = _appinfo_find(uid, appid);
	if (ai == NULL)
		return;

	bundle_del(kb, AUL_SVC_K_PKG_NAME);
	bundle_add(kb, AUL_SVC_K_PKG_NAME, appid);

	effective_appid = _appinfo_get_value(ai, AIT_EFFECTIVE_APPID);
	if (effective_appid == NULL)
		return;

	effective_ai = _appinfo_find(uid, effective_appid);
	if (effective_ai == NULL)
		return;

	pkgid = _appinfo_get_value(ai, AIT_PKGID);
	effective_pkgid = _appinfo_get_value(effective_ai, AIT_PKGID);
	if (pkgid && effective_pkgid && strcmp(pkgid, effective_pkgid) == 0) {
		_D("use effective appid instead of the real appid");
		bundle_del(kb, AUL_K_APPID);
		bundle_add(kb, AUL_K_APPID, effective_appid);
	}
}

static void __set_real_appid(uid_t uid, bundle *kb)
{
	const char *alias_appid;
	const char *appid;
	const char *alias_info;
	app_property_h app_property;

	alias_appid = bundle_get_val(kb, AUL_K_APPID);
	if (alias_appid == NULL)
		return;

	alias_info = bundle_get_val(kb, AUL_SVC_K_ALIAS_INFO);
	if (alias_info && strcmp(alias_info, "disable") == 0)
		return;

	app_property = _app_property_find(uid);
	if (app_property == NULL)
		return;

	appid = _app_property_get_real_appid(app_property, alias_appid);
	if (appid == NULL)
		return;

	_D("alias_appid(%s), appid(%s)", alias_appid, appid);
	bundle_del(kb, AUL_K_ORG_APPID);
	bundle_add(kb, AUL_K_ORG_APPID, alias_appid);
	bundle_del(kb, AUL_K_APPID);
	bundle_add(kb, AUL_K_APPID, appid);
}

static void __check_new_instance(bundle *kb, bool *new_instance)
{
	const char *str;

	str = bundle_get_val(kb, AUL_K_NEW_INSTANCE);
	if (str && !strcmp(str, "true"))
		*new_instance = true;
	else
		*new_instance = false;
}

static int __dispatch_app_start(request_h req)
{
	const char *appid;
	int ret;
	bundle *kb;
	bool pending = false;
	bool bg_launch = false;
	bool new_instance = false;
	request_reply_h reply;

	kb = _request_get_bundle(req);
	if (kb == NULL)
		return -1;

	__set_real_appid(_request_get_target_uid(req), kb);
	__set_effective_appid(_request_get_target_uid(req), kb);

	bundle_del(kb, AUL_K_NEW_INSTANCE);
	_noti_send("launch.app_start.start", 0, 0, req, kb);
	__check_new_instance(kb, &new_instance);

	appid = bundle_get_val(kb, AUL_K_APPID);
	ret = _launch_start_app(appid, req, &pending, &bg_launch, new_instance);
	if (ret <= 0)
		_noti_send("launch.fail", ret, 0, NULL, NULL);

	/* add pending list to wait app launched successfully */
	if (pending) {
		reply = _request_reply_create(req, ret, ret,
				_request_get_cmd(req));
		if (reply == NULL)
			return -1;

		_noti_send("launch.app_start.pend", ret, bg_launch, req, (bundle *)reply);

		if (_request_reply_append(ret, reply) < 0) {
			_request_send_result(req, ret);
			return -1;
		}

		return 0;
	}

	_noti_send("launch.app_start.end", ret, bg_launch, req, kb);

	return 0;
}

static int __get_caller_uid(bundle *kb, uid_t *uid)
{
	const char *val;

	val = bundle_get_val(kb, AUL_K_ORG_CALLER_UID);
	if (val == NULL)
		val = bundle_get_val(kb, AUL_K_CALLER_UID);

	if (val == NULL) {
		_E("Failed to get caller uid");
		return -1;
	}

	*uid = atol(val);
	_D("caller uid(%d)", *uid);

	return 0;
}

static void __set_instance_id(bundle *kb)
{
	app_status_h app_status;
	const char *instance_id;
	const char *callee_pid;
	int pid;

	callee_pid = bundle_get_val(kb, AUL_K_FWD_CALLEE_PID);
	if (callee_pid == NULL)
		callee_pid = bundle_get_val(kb, AUL_K_CALLEE_PID);

	if (callee_pid == NULL) {
		_E("Failed to get callee pid");
		return;
	}

	pid = atoi(callee_pid);
	if (pid <= 0)
		return;

	app_status = _app_status_find(pid);
	if (app_status == NULL)
		return;

	instance_id = _app_status_get_instance_id(app_status);
	if (instance_id == NULL)
		return;

	bundle_del(kb, AUL_K_INSTANCE_ID);
	bundle_add(kb, AUL_K_INSTANCE_ID, instance_id);
	_D("instance_id(%s)", instance_id);
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

static int __dispatch_app_result(request_h req)
{
	bundle *kb;
	int pid;
	int pgid;
	char tmp_pid[MAX_PID_STR_BUFSZ];
	int res;
	const char *appid;
	uid_t target_uid = _request_get_target_uid(req);
	app_status_h app_status;

	kb = _request_get_bundle(req);
	if (kb == NULL)
		return -1;

	pid = __get_caller_pid(kb);
	if (pid < 0)
		return AUL_R_ERROR;

	pgid = getpgid(_request_get_pid(req));
	if (pgid > 0) {
		snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", pgid);
		bundle_del(kb, AUL_K_CALLEE_PID);
		bundle_add(kb, AUL_K_CALLEE_PID, tmp_pid);
	}

	if (__get_caller_uid(kb, &target_uid) < 0)
		return AUL_R_ERROR;

	__set_instance_id(kb);
	app_status = _app_status_find(getpgid(pid));
	appid = _app_status_get_appid(app_status);

	_noti_send("launch.app_result.start", pgid, target_uid, (void *)appid, kb);
	res = aul_sock_send_bundle(pid, target_uid, _request_get_cmd(req), kb,
			AUL_SOCK_NOREPLY);
	if (res < 0)
		res = AUL_R_ERROR;

	_noti_send("launch.app_result.end", pid, target_uid, GINT_TO_POINTER(res), NULL);

	return 0;
}

static int __dispatch_app_pause(request_h req)
{
	const char *appid;
	bundle *kb;
	int ret;
	app_status_h app_status;

	kb = _request_get_bundle(req);
	if (kb == NULL)
		return -1;

	appid = bundle_get_val(kb, AUL_K_APPID);
	app_status = _app_status_find_by_appid(appid,
			_request_get_target_uid(req));
	ret = _app_status_get_pid(app_status);
	if (ret > 0)
		ret = _pause_app(ret, req);
	else
		_E("%s is not running", appid);

	return 0;
}

static int __app_process_by_pid(request_h req, const char *pid_str,
		bool *pending)
{
	int pid;
	int ret;
	int dummy;
	const char *appid;
	const char *pkgid;
	const char *type;
	const struct appinfo *ai;
	uid_t target_uid = _request_get_target_uid(req);
	app_status_h app_status;

	if (pid_str == NULL)
		return -1;

	pid = atoi(pid_str);
	if (pid <= 1) {
		_E("invalid pid");
		return -1;
	}

	app_status = _app_status_find(pid);
	if (app_status == NULL) {
		_E("pid %d is not an application", pid);
		_request_send_result(req, -1);
		return -1;
	}

	appid = _app_status_get_appid(app_status);
	ai = _appinfo_find(target_uid, appid);
	if (ai == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	pkgid = _appinfo_get_value(ai, AIT_PKGID);
	type = _appinfo_get_value(ai, AIT_COMPTYPE);

	switch (_request_get_cmd(req)) {
	case APP_RESUME_BY_PID:
	case APP_RESUME_BY_PID_ASYNC:
	case APP_PAUSE_BY_PID:
		aul_send_app_resume_request_signal(pid, appid, pkgid, type);
		break;
	default:
		aul_send_app_terminate_request_signal(pid, appid, pkgid, type);
		break;
	}

	switch (_request_get_cmd(req)) {
	case APP_RESUME_BY_PID_ASYNC:
		_request_send_result(req, 0);
		ret = _resume_app(pid, req);
		break;
	case APP_RESUME_BY_PID:
		ret = _resume_app(pid, req);
		break;
	case APP_TERM_BY_PID:
		ret = _term_app(pid, req);
		break;
	case APP_TERM_BY_PID_WITHOUT_RESTART:
		if (_app_status_get_app_type(app_status) == AT_WIDGET_APP)
			_app_status_update_is_exiting(app_status, true);
		ret = _term_app(pid, req);
		break;
	case APP_TERM_BGAPP_BY_PID:
		ret = _term_bgapp(pid, req);
		break;
	case APP_KILL_BY_PID:
		ret = __send_to_sigkill(pid, target_uid);
		if (ret < 0)
			_E("fail to killing - %d\n", pid);
		_app_status_update_status(app_status, STATUS_DYING, false, true);
		_request_send_result(req, ret);
		break;
	case APP_TERM_REQ_BY_PID:
		ret = _term_req_app(pid, req);
		break;
	case APP_TERM_BY_PID_ASYNC:
		ret = aul_sock_send_raw(pid, target_uid, _request_get_cmd(req),
				(unsigned char *)&dummy, sizeof(int),
				AUL_SOCK_NOREPLY);
		if (ret < 0)
			_D("terminate req packet send error");

		_request_send_result(req, ret);
		break;
	case APP_PAUSE_BY_PID:
		ret = _pause_app(pid, req);
		break;
	case APP_TERM_BY_PID_SYNC:
	case APP_TERM_BY_PID_SYNC_WITHOUT_RESTART:
		if (_app_status_get_status(app_status) == STATUS_DYING) {
			_W("%d is dying", pid);
			if (pending)
				*pending = true;
			ret = 0;
			break;
		}
		ret = _term_app_v2(pid, req, pending);
		break;
	default:
		_E("unknown command: %d", _request_get_cmd(req));
		ret = -1;
	}

	return ret;
}

static int __dispatch_app_process_by_pid(request_h req)
{
	const char *appid;
	bundle *kb;

	kb = _request_get_bundle(req);
	if (kb == NULL)
		return -1;

	appid = bundle_get_val(kb, AUL_K_APPID);
	__app_process_by_pid(req, appid, NULL);

	return 0;
}

static int __dispatch_app_term_async(request_h req)
{
	const char *appid;
	bundle *kb;
	const char *term_pid;
	struct appinfo *ai;
	app_status_h app_status;
	const char *ai_status;

	kb = _request_get_bundle(req);
	if (kb == NULL)
		return -1;

	term_pid = bundle_get_val(kb, AUL_K_APPID);
	app_status = _app_status_find(atoi(term_pid));
	appid = _app_status_get_appid(app_status);
	ai = _appinfo_find(_request_get_target_uid(req), appid);
	if (ai) {
		ai_status = _appinfo_get_value(ai, AIT_STATUS);
		if (ai_status && strcmp(ai_status, "blocking") != 0)
			_appinfo_set_value(ai, AIT_STATUS, "norestart");
		__app_process_by_pid(req, term_pid, NULL);
	}

	return 0;
}

static int __dispatch_app_term(request_h req)
{
	const char *appid;
	bundle *kb;

	kb = _request_get_bundle(req);
	if (kb == NULL)
		return -1;

	appid = bundle_get_val(kb, AUL_K_APPID);
	__app_process_by_pid(req, appid, NULL);

	return 0;
}

static int __dispatch_app_term_sync(request_h req)
{
	int ret;
	int pid;
	const char *appid;
	bundle *kb;
	bool pending = false;
	request_reply_h reply;

	kb = _request_get_bundle(req);
	if (kb == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	appid = bundle_get_val(kb, AUL_K_APPID);
	ret = __app_process_by_pid(req, appid, &pending);
	if (ret < 0)
		return -1;

	/* add pending list to wait app terminated successfully */
	if (pending) {
		pid = atoi(appid);
		reply = _request_reply_create(req, pid, -EAGAIN,
				_request_get_cmd(req));
		if (reply == NULL)
			return -1;

		_request_reply_append(pid, reply);
		_request_reply_reset_pending_timer(req, -1, pid);
	}

	return 0;
}

static int __dispatch_app_term_sync_without_restart(request_h req)
{
	int ret = -1;
	const char *appid;
	const char *term_pid;
	const char *component_type;
	struct appinfo *ai;
	app_status_h app_status;
	const char *ai_status;

	term_pid = bundle_get_val(_request_get_bundle(req), AUL_K_APPID);
	if (term_pid == NULL)
		goto exception;

	app_status = _app_status_find(atoi(term_pid));
	if (app_status == NULL)
		goto exception;

	appid = _app_status_get_appid(app_status);
	if (appid == NULL)
		goto exception;

	ai = _appinfo_find(_request_get_target_uid(req), appid);
	if (ai == NULL)
		goto exception;

	component_type = _appinfo_get_value(ai, AIT_COMPTYPE);
	if (!component_type)
		goto exception;

	ret = __dispatch_app_term_sync(req);
	if (ret < 0)
		return ret;

	if (strcmp(component_type, APP_TYPE_SERVICE) == 0) {
		ai_status = _appinfo_get_value(ai, AIT_STATUS);
		if (ai_status && strcmp(ai_status, "blocking") != 0)
			_appinfo_set_value(ai, AIT_STATUS, "norestart");
	}
	return 0;

exception:
	_request_send_result(req, ret);
	return ret;
}

static int __dispatch_app_startup_signal(request_h req)
{
	int pid = _request_get_pid(req);
	app_status_h app_status;

	_I("[START] pid(%d)", pid);
	app_status = _app_status_find(pid);
	if (app_status == NULL)
		return -1;

	_app_status_update_is_starting(app_status, true);
	if (_app_status_get_app_type(app_status) == AT_UI_APP &&
			_app_status_get_status(app_status) != STATUS_VISIBLE)
		__launch_add_fgmgr(pid);

	_request_reply_reset_pending_timer(req, PENDING_REQUEST_TIMEOUT, pid);
	_noti_send("launch.app_startup_signal.end", pid, 0, req, NULL);
	_I("[END] pid(%d)", pid);

	return 0;
}

static const char *__convert_operation_to_privilege(const char *operation)
{
	if (operation == NULL)
		return NULL;
	else if (!strcmp(operation, AUL_SVC_OPERATION_DOWNLOAD))
		return PRIVILEGE_DOWNLOAD;
	else if (!strcmp(operation, AUL_SVC_OPERATION_CALL))
		return PRIVILEGE_CALL;

	return NULL;
}

struct checker_info {
	caller_info_h caller;
	request_h req;
	int result;
};

static int __appcontrol_privilege_func(const char *privilege_name,
		void *user_data)
{
	int ret;
	struct checker_info *info = (struct checker_info *)user_data;

	ret = _cynara_simple_checker(info->caller, info->req,
			(void *)privilege_name);
	if (ret >= 0 && info->result == AMD_CYNARA_UNKNOWN)
		return ret;

	info->result = ret;
	return ret;
}

static int __appcontrol_checker(caller_info_h info, request_h req,
		void *data)
{
	bundle *appcontrol;
	const char *op_priv = NULL;
	const char *appid = NULL;
	char *op = NULL;
	int ret;
	const char *target_appid;
	bool unknown = false;
	const char *syspopup;
	const char *below;
	struct checker_info checker = {
		.caller = info,
		.req = req,
		.result = AMD_CYNARA_ALLOWED
	};

	appcontrol = _request_get_bundle(req);
	if (appcontrol == NULL)
		return AMD_CYNARA_ALLOWED;

	if (bundle_get_type(appcontrol, AUL_K_SDK) != BUNDLE_TYPE_NONE) {
		target_appid = bundle_get_val(appcontrol, AUL_K_APPID);

		if (target_appid && strcmp(target_appid, APPID_WIDGET_VIEWER_SDK) != 0) {
			ret = _cynara_check_privilege_offline(req, target_appid,
					"http://tizen.org/privilege/internal/appdebugging");
			if (ret != AMD_CYNARA_ALLOWED) {
				_E("appdebugging privilege is needed to debug");
				return ret;
			}
		}
	}

	ret = _cynara_sub_checker_check("appcontrol", info, req);
	if (ret != AMD_CYNARA_CONTINUE)
		return ret;

	ret = bundle_get_str(appcontrol, AUL_SVC_K_OPERATION, &op);
	if (ret == BUNDLE_ERROR_NONE)
		op_priv = __convert_operation_to_privilege(op);
	if (op_priv) {
		ret = _cynara_simple_checker(info, req, (void *)op_priv);
		if (ret < 0)
			return ret;
		if (ret == AMD_CYNARA_UNKNOWN)
			unknown = true;
	}

	appid = bundle_get_val(appcontrol, AUL_K_APPID);
	if (appid && op) {
		ret = pkgmgrinfo_appinfo_usr_foreach_appcontrol_privileges(
				appid, op, __appcontrol_privilege_func,
				&checker, _request_get_target_uid(req));
		if (ret < 0) {
			_E("Failed to get appcontrol privileges");
			return ret;
		}

		if (checker.result < 0)
			return checker.result;
		else if (checker.result == AMD_CYNARA_UNKNOWN)
			unknown = true;
	}

	syspopup = bundle_get_val(appcontrol, SYSPOPUP_NAME);
	below = bundle_get_val(appcontrol, AUL_SVC_K_RELOCATE_BELOW);
	if (below || syspopup) {
		ret = _cynara_simple_checker(info, req, PRIVILEGE_PLATFORM);
		if (ret < 0)
			return ret;
		if (ret == AMD_CYNARA_UNKNOWN)
			unknown = true;
	}

	ret = _cynara_simple_checker(info, req, PRIVILEGE_APPMANAGER_LAUNCH);
	if (unknown && ret >= 0)
		return AMD_CYNARA_UNKNOWN;

	return ret;
}

static int __term_req_checker(caller_info_h info, request_h req,
		void *data)
{
	app_status_h app_status;
	int caller_pid = _request_get_pid(req);
	int target_pid = -1;
	int first_caller_pid;
	const char *pid_str;
	bundle *b;

	b = _request_get_bundle(req);
	if (!b) {
		_E("Failed to get bundle");
		return AMD_CYNARA_DENIED;
	}

	pid_str = bundle_get_val(b, AUL_K_APPID);
	if (!pid_str) {
		_E("Failed to get process ID");
		return AMD_CYNARA_DENIED;
	}

	target_pid = atoi(pid_str);
	if (target_pid < 1) {
		_E("Process ID: %d", target_pid);
		return AMD_CYNARA_DENIED;
	}

	app_status = _app_status_find(target_pid);
	if (!app_status) {
		_E("Failed to find app status. pid(%d)", target_pid);
		return AMD_CYNARA_DENIED;
	}

	if (_app_status_get_app_type(app_status) != AT_UI_APP) {
		_E("Target application is not UI application");
		return AMD_CYNARA_DENIED;
	}

	first_caller_pid = _app_status_get_org_caller_pid(app_status);
	if (first_caller_pid != caller_pid &&
			first_caller_pid != getpgid(caller_pid)) {
		_E("Request denied. caller(%d)", caller_pid);
		return AMD_CYNARA_DENIED;
	}

	return AMD_CYNARA_ALLOWED;
}

static request_cmd_dispatch __dispatch_table[] = {
	{
		.cmd = APP_START,
		.callback = __dispatch_app_start
	},
	{
		.cmd = APP_START_ASYNC,
		.callback = __dispatch_app_start
	},
	{
		.cmd = APP_START_RES_ASYNC,
		.callback = __dispatch_app_start
	},
	{
		.cmd = APP_START_RES,
		.callback = __dispatch_app_start
	},
	{
		.cmd = APP_OPEN,
		.callback = __dispatch_app_start
	},
	{
		.cmd = APP_RESUME,
		.callback = __dispatch_app_start
	},
	{
		.cmd = APP_RESUME_BY_PID,
		.callback = __dispatch_app_process_by_pid
	},
	{
		.cmd = APP_RESUME_BY_PID_ASYNC,
		.callback = __dispatch_app_process_by_pid
	},
	{
		.cmd = APP_TERM_BY_PID,
		.callback = __dispatch_app_term
	},
	{
		.cmd = APP_TERM_BY_PID_WITHOUT_RESTART,
		.callback = __dispatch_app_term_async
	},
	{
		.cmd = APP_TERM_BY_PID_SYNC,
		.callback = __dispatch_app_term_sync
	},
	{
		.cmd = APP_TERM_BY_PID_SYNC_WITHOUT_RESTART,
		.callback = __dispatch_app_term_sync_without_restart
	},
	{
		.cmd = APP_TERM_REQ_BY_PID,
		.callback = __dispatch_app_process_by_pid
	},
	{
		.cmd = APP_TERM_BY_PID_ASYNC,
		.callback = __dispatch_app_term_async
	},
	{
		.cmd = APP_TERM_BGAPP_BY_PID,
		.callback = __dispatch_app_term
	},
	{
		.cmd = APP_RESULT,
		.callback = __dispatch_app_result
	},
	{
		.cmd = APP_CANCEL,
		.callback = __dispatch_app_result
	},
	{
		.cmd = APP_PAUSE,
		.callback = __dispatch_app_pause
	},
	{
		.cmd = APP_PAUSE_BY_PID,
		.callback = __dispatch_app_process_by_pid
	},
	{
		.cmd = APP_KILL_BY_PID,
		.callback = __dispatch_app_term
	},
	{
		.cmd = APP_STARTUP_SIGNAL,
		.callback = __dispatch_app_startup_signal
	},
	{
		.cmd = APP_SEND_LAUNCH_REQUEST,
		.callback = __dispatch_app_start
	},
};

static cynara_checker __cynara_checkers[] = {
	{
		.cmd = APP_OPEN,
		.checker = __appcontrol_checker,
		.data = NULL
	},
	{
		.cmd = APP_RESUME,
		.checker = __appcontrol_checker,
		.data = NULL
	},
	{
		.cmd = APP_START,
		.checker = __appcontrol_checker,
		.data = NULL
	},
	{
		.cmd = APP_START_RES,
		.checker = __appcontrol_checker,
		.data = NULL
	},
	{
		.cmd = APP_TERM_BY_PID_WITHOUT_RESTART,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_APPMANAGER_KILL
	},
	{
		.cmd = APP_TERM_BY_PID_ASYNC,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_APPMANAGER_KILL
	},
	{
		.cmd = APP_TERM_BY_PID,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_APPMANAGER_KILL
	},
	{
		.cmd = APP_KILL_BY_PID,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_APPMANAGER_KILL
	},
	{
		.cmd = APP_TERM_BGAPP_BY_PID,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_APPMANAGER_KILL_BGAPP
	},
	{
		.cmd = APP_START_ASYNC,
		.checker = __appcontrol_checker,
		.data = NULL
	},
	{
		.cmd = APP_TERM_BY_PID_SYNC,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_APPMANAGER_KILL
	},
	{
		.cmd = APP_TERM_BY_PID_SYNC_WITHOUT_RESTART,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_APPMANAGER_KILL
	},
	{
		.cmd = APP_START_RES_ASYNC,
		.checker = __appcontrol_checker,
		.data = NULL
	},
	{
		.cmd = APP_TERM_REQ_BY_PID,
		.checker = __term_req_checker,
		.data = NULL
	},
	{
		.cmd = APP_RESUME_BY_PID,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_APPMANAGER_LAUNCH
	},
	{
		.cmd = APP_RESUME_BY_PID_ASYNC,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_APPMANAGER_LAUNCH
	},
	{
		.cmd = APP_PAUSE,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_APPMANAGER_LAUNCH
	},
	{
		.cmd = APP_PAUSE_BY_PID,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_APPMANAGER_LAUNCH
	},
	{
		.cmd = APP_SEND_LAUNCH_REQUEST,
		.checker = __appcontrol_checker,
		.data = NULL
	},
};

static int __on_app_status_cleanup(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	app_status_h app_status = arg3;
	int pid;

	pid = _app_status_get_pid(app_status);
	__launch_remove_fgmgr(pid);

	return 0;
}

static int __default_launcher(bundle *b, uid_t uid, void *data)
{
	int r;

	if (!b) {
		_E("Invalid parameter");
		return -1;
	}

	r = _send_cmd_to_launchpad(LAUNCHPAD_PROCESS_POOL_SOCK, uid,
			PAD_CMD_LAUNCH, b);
	return r;
}

int _launch_init(void)
{
	int ret;

	_D("_launch_init");

	_launchpad_set_launcher(__default_launcher, NULL);

	ret = __listen_app_status_signal(NULL);
	if (ret < 0)
		_signal_add_initializer(__listen_app_status_signal, NULL);

	ret = __listen_poweroff_state_signal(NULL);
	if (ret < 0)
		_signal_add_initializer(__listen_poweroff_state_signal, NULL);

	ret = _request_register_cmds(__dispatch_table,
			ARRAY_SIZE(__dispatch_table));
	if (ret < 0) {
		_E("Failed to register cmds");
		return -1;
	}

	ret = _cynara_register_checkers(__cynara_checkers,
			ARRAY_SIZE(__cynara_checkers));
	if (ret < 0) {
		_E("Failed to register checkers");
		return -1;
	}

	_noti_listen("app_status.cleanup", __on_app_status_cleanup);

	return 0;
}

static int __check_ver(const char *required, const char *actual)
{
	int ret;

	if (required && actual) {
		ret = strverscmp(required, actual);
		if (ret < 1)
			return 1;
	}

	return 0;
}

static int __get_prelaunch_attribute(struct appinfo *ai,
		const char *appid, uid_t uid)
{
	int attribute_val = RESOURCED_BG_MANAGEMENT_ATTRIBUTE;
	const char *api_version;
	const char *comp;
	const char *pkg_type;
	bool system = false;
	app_property_h prop;
	bool activate;

	api_version = _appinfo_get_value(ai, AIT_API_VERSION);
	if (api_version && __check_ver("2.4", api_version))
		attribute_val |= RESOURCED_API_VER_2_4_ATTRIBUTE;

	comp = _appinfo_get_value(ai, AIT_COMPTYPE);
	if (comp && !strcmp(comp, APP_TYPE_SERVICE))
		attribute_val |= RESOURCED_ATTRIBUTE_SERVICE_APP;

	pkg_type = _appinfo_get_value(ai, AIT_PKGTYPE);
	if (pkg_type && !strcmp(pkg_type, "wgt")) {
		attribute_val |= RESOURCED_ATTRIBUTE_LARGEMEMORY;
		attribute_val |= RESOURCED_ATTRIBUTE_WEB_APP;
	}

	_appinfo_get_boolean(ai, AIT_SYSTEM, &system);
	if (!system)
		attribute_val |= RESOURCED_ATTRIBUTE_DOWNLOAD_APP;

	prop = _app_property_find(uid);
	if (prop) {
		activate = _app_property_metadata_query_activation(prop, appid,
				METADATA_LARGEMEMORY);
		if (activate)
			attribute_val |= RESOURCED_ATTRIBUTE_LARGEMEMORY;
		activate = _app_property_metadata_query_activation(prop, appid,
				METADATA_OOMTERMINATION);
		if (activate)
			attribute_val |= RESOURCED_ATTRIBUTE_OOMTERMINATION;
		activate = _app_property_metadata_query_activation(prop, appid,
				METADATA_VIPAPP);
		if (activate && __check_platform_app(ai, uid))
			attribute_val |= RESOURCED_ATTRIBUTE_VIP_APP;

	}

	_D("api-version: %s", api_version);
	_D("prelaunch attribute %d%d%d%d%d%d",
			(attribute_val & 0x20) >> 5,
			(attribute_val & 0x10) >> 4,
			(attribute_val & 0x8) >> 3,
			(attribute_val & 0x4) >> 2,
			(attribute_val & 0x2) >> 1,
			(attribute_val & 0x1));

	return attribute_val;
}

static int __get_background_category(const struct appinfo *ai)
{
	int category = 0x0;

	category = (intptr_t)_appinfo_get_value(ai, AIT_BG_CATEGORY);

	_D("background category: %#x", category);

	return category;
}

static void __set_caller_appinfo(const char *caller_appid, int caller_pid,
		uid_t caller_uid, bundle *kb)
{
	char buf[MAX_PID_STR_BUFSZ];

	snprintf(buf, sizeof(buf), "%d", caller_pid);
	bundle_del(kb, AUL_K_CALLER_PID);
	bundle_add(kb, AUL_K_CALLER_PID, buf);

	snprintf(buf, sizeof(buf), "%d", caller_uid);
	bundle_del(kb, AUL_K_CALLER_UID);
	bundle_add(kb, AUL_K_CALLER_UID, buf);

	if (caller_appid) {
		bundle_del(kb, AUL_K_CALLER_APPID);
		bundle_add(kb, AUL_K_CALLER_APPID, caller_appid);
	}
}

static const char *__get_caller_appid(int caller_pid, uid_t caller_uid)
{
	app_status_h app_status;

	app_status = _app_status_find(caller_pid);
	if (app_status == NULL && caller_uid >= REGULAR_UID_MIN)
		app_status = _app_status_find(getpgid(caller_pid));

	return _app_status_get_appid(app_status);
}

static int __check_caller(pid_t caller_pid)
{
	char attr[512] = { 0, };
	int r;

	r = _proc_get_attr(caller_pid, attr, sizeof(attr));
	if (r < 0) {
		_E("Failed to get attr. pid(%d)", caller_pid);
		return -EILLEGALACCESS;
	}

	if (!strncmp(attr, "User::Pkg::", strlen("User::Pkg::"))) {
		_E("Reject request. caller(%d:%s)", caller_pid, attr);
		return -EILLEGALACCESS;
	}

	return 0;
}

static int __check_executable(const struct appinfo *ai)
{
	const char *status;
	int enable;
	int ret;

	status = _appinfo_get_value(ai, AIT_STATUS);
	if (status == NULL)
		return -1;

	if (!strcmp(status, "blocking") || !strcmp(status, "restart")) {
		_D("Blocking");
		return -EREJECTED;
	}

	ret = _appinfo_get_int_value(ai, AIT_ENABLEMENT, &enable);
	if (ret == 0 && !(enable & APP_ENABLEMENT_MASK_ACTIVE)) {
		_D("Disabled");
		return -EREJECTED;
	}

	return 0;
}

static void __set_appinfo_for_launchpad(const struct appinfo *ai, bundle *kb)
{
	const char *str;

	str = _appinfo_get_value(ai, AIT_HWACC);
	if (str) {
		bundle_del(kb, AUL_K_HWACC);
		bundle_add(kb, AUL_K_HWACC, str);
	}

	str = _appinfo_get_value(ai, AIT_ROOT_PATH);
	if (str) {
		bundle_del(kb, AUL_K_ROOT_PATH);
		bundle_add(kb, AUL_K_ROOT_PATH, str);
	}

	str = _appinfo_get_value(ai, AIT_EXEC);
	if (str) {
		bundle_del(kb, AUL_K_EXEC);
		bundle_add(kb, AUL_K_EXEC, str);
	}

	str = _appinfo_get_value(ai, AIT_PKGTYPE);
	if (str) {
		bundle_del(kb, AUL_K_PACKAGETYPE);
		bundle_add(kb, AUL_K_PACKAGETYPE, str);
	}

	str = _appinfo_get_value(ai, AIT_PKGID);
	if (str) {
		bundle_del(kb, AUL_K_PKGID);
		bundle_add(kb, AUL_K_PKGID, str);
	}

	str = _appinfo_get_value(ai, AIT_POOL);
	if (str) {
		bundle_del(kb, AUL_K_INTERNAL_POOL);
		bundle_add(kb, AUL_K_INTERNAL_POOL, str);
	}

	str = _appinfo_get_value(ai, AIT_COMPTYPE);
	if (str) {
		bundle_del(kb, AUL_K_COMP_TYPE);
		bundle_add(kb, AUL_K_COMP_TYPE, str);
	}

	str = _appinfo_get_value(ai, AIT_APPTYPE);
	if (str) {
		bundle_del(kb, AUL_K_APP_TYPE);
		bundle_add(kb, AUL_K_APP_TYPE, str);
	}

	str = _appinfo_get_value(ai, AIT_API_VERSION);
	if (str) {
		bundle_del(kb, AUL_K_API_VERSION);
		bundle_add(kb, AUL_K_API_VERSION, str);
	}

	if (_config_get_tizen_profile() == TIZEN_PROFILE_WEARABLE) {
		bundle_del(kb, AUL_K_PROFILE);
		bundle_add(kb, AUL_K_PROFILE, "wearable");
	}

	str = _appinfo_get_value(ai, AIT_GLOBAL);
	if (str) {
		bundle_del(kb, AUL_K_IS_GLOBAL);
		bundle_add(kb, AUL_K_IS_GLOBAL, str);
	}

	str = _appinfo_get_value(ai, AIT_STORAGE_TYPE);
	if (str) {
		bundle_del(kb, AUL_K_INSTALLED_STORAGE);
		bundle_add(kb, AUL_K_INSTALLED_STORAGE, str);
	}
}

static int __get_app_status(struct launch_s *handle, request_h req,
		const char *comp_type, const char *caller_appid)
{
	const char *widget_viewer;
	const char *multiple;
	int *target_pid = NULL;
	size_t target_pid_sz;
	bundle *kb = _request_get_bundle(req);
	int caller_pid = _request_get_pid(req);
	uid_t target_uid = _request_get_target_uid(req);
	int ret;

	if (caller_appid && strcmp(comp_type, APP_TYPE_WIDGET) == 0) {
		handle->is_subapp = true;
		widget_viewer = bundle_get_val(kb, AUL_K_WIDGET_VIEWER);
		if (widget_viewer && strcmp(widget_viewer, caller_appid) == 0) {
			_D("widget_viewer(%s)", widget_viewer);
			handle->app_status = _app_status_find_with_org_caller(
					handle->appid, target_uid, caller_pid);
		} else {
			ret = bundle_get_byte(kb, AUL_K_TARGET_PID,
					(void **)&target_pid, &target_pid_sz);
			if (ret != BUNDLE_ERROR_NONE) {
				_E("Cannot launch widget app");
				return -EREJECTED;
			}

			handle->app_status = _app_status_find(*target_pid);
			if (handle->app_status == NULL) {
				_E("Cannot find widget app(%d)", *target_pid);
				return -EREJECTED;
			}
		}
	} else if (strcmp(comp_type, APP_TYPE_WATCH) == 0) {
		handle->is_subapp = true;
		widget_viewer = bundle_get_val(kb, AUL_K_WIDGET_VIEWER);
		if (widget_viewer && caller_appid &&
				!strcmp(widget_viewer, caller_appid)) {
			_D("watch_viewer(%s)", widget_viewer);
			handle->app_status = _app_status_find_with_org_caller(
					handle->appid, target_uid, caller_pid);
		} else {
			ret = bundle_get_byte(kb, AUL_K_TARGET_PID,
					(void **)&target_pid, &target_pid_sz);
			if (ret != BUNDLE_ERROR_NONE) {
				handle->app_status =
					_app_status_find_by_appid_v2(
							handle->appid,
							target_uid);
			} else {
				handle->app_status =
					_app_status_find(*target_pid);
			}

			if (handle->app_status == NULL) {
				_E("Cannot find watch app(%s)", handle->appid);
				return -EREJECTED;
			}
		}
	} else {
		handle->instance_id = bundle_get_val(kb, AUL_K_INSTANCE_ID);
		if (handle->instance_id) {
			handle->app_status = _app_status_find_by_instance_id(
					handle->appid, handle->instance_id,
					target_uid);
			if (!handle->app_status && !handle->new_instance) {
				_E("Failed to find app instance(%s)",
						handle->instance_id);
				return -EREJECTED;
			}
		} else {
			multiple = _appinfo_get_value(handle->ai, AIT_MULTI);
			if (multiple == NULL || !strcmp(multiple, "false")) {
				handle->app_status = _app_status_find_by_appid(
						handle->appid, target_uid);
			}
		}
	}

	handle->pid = _app_status_get_pid(handle->app_status);

	return 0;
}

static int __prepare_starting_app(struct launch_s *handle, request_h req,
		const char *appid, bool new_instance)
{
	int ret;
	int status;
	const char *pkgid;
	const char *comp_type;
	const char *caller_appid = NULL;
	const char *bg_launch;
	int cmd = _request_get_cmd(req);
	int caller_pid = _request_get_pid(req);
	uid_t caller_uid = _request_get_uid(req);
	uid_t target_uid = _request_get_target_uid(req);
	bundle *kb = _request_get_bundle(req);
	const struct appinfo *caller_ai;

	if (__launch_mode != LAUNCH_MODE_NORMAL) {
		_E("Launch mode is not normal: %d", __launch_mode);
		return -EREJECTED;
	}

	handle->new_instance = new_instance;
	handle->appid = appid;
	handle->ai = _appinfo_find(target_uid, appid);
	if (handle->ai == NULL) {
		_D("Failed to find appinfo of %s", appid);
		return -ENOENT;
	}

	ret = __check_executable(handle->ai);
	if (ret < 0)
		return -1;

	if (caller_uid >= REGULAR_UID_MIN) {
		caller_appid = __get_caller_appid(caller_pid, caller_uid);
		if (!caller_appid) {
			ret = __check_caller(caller_pid);
			if (ret != 0)
				return ret;
		}
	}

	if (caller_appid) {
		caller_ai = _appinfo_find(caller_uid, caller_appid);
		if (caller_ai) {
			comp_type = _appinfo_get_value(caller_ai, AIT_COMPTYPE);
			if (comp_type && !strcmp(comp_type, APP_TYPE_UI))
				bundle_del(kb, AUL_SVC_K_CAN_BE_LEADER);
		}
	}
	__set_caller_appinfo(caller_appid, caller_pid, caller_uid, kb);

	ret = __compare_signature(handle->ai, cmd, target_uid, appid,
			caller_appid);
	if (ret < 0)
		return ret;

	ret = _noti_send("launch.prepare.start", 0, 0,
			(void *)(handle->ai), NULL);
	if (ret < 0) {
		_E("Unable to launch %s (Some listeners don't want to continue)",
				handle->appid);
		return -1;
	}

	bg_launch = bundle_get_val(kb, AUL_SVC_K_BG_LAUNCH);
	if (bg_launch && strcmp(bg_launch, "enable") == 0)
		handle->bg_launch = true;

	comp_type = _appinfo_get_value(handle->ai, AIT_COMPTYPE);
	if (comp_type == NULL)
		return -1;

	ret = __get_app_status(handle, req, comp_type, caller_appid);
	if (ret < 0)
		return ret;

	if (strcmp(comp_type, APP_TYPE_UI) == 0) {
		status = _app_status_get_status(handle->app_status);
		ret = _noti_send("launch.prepare.ui.start", status, target_uid,
				handle, kb);
		if (ret < 0)
			return -EILLEGALACCESS;

		if (handle->pid > 0) {
			handle->app_status = _app_status_find(handle->pid);
			status = _app_status_get_status(handle->app_status);
		}

		if (handle->pid <= 0 || status == STATUS_DYING)
			handle->new_process = true;

		if (_noti_send("launch.prepare.ui.end",
				handle->bg_launch, caller_pid,
				(void *)(handle->app_status), NULL) < 0)
			return -1;
	} else if (caller_appid && strcmp(comp_type, APP_TYPE_SERVICE) == 0) {
		pkgid = _appinfo_get_value(handle->ai, AIT_PKGID);
		ret = __check_execute_permission(pkgid, caller_appid,
				target_uid, req);
		if (ret < 0)
			return ret;
		if (_noti_send("launch.prepare.service", 0, 0, req, NULL) < 0)
			return -1;
	} else if (caller_appid && strcmp(comp_type, APP_TYPE_WIDGET) == 0) {
		if (_noti_send("launch.prepare.widget", 0, 0, req, NULL) < 0)
			return -1;
	}

	if (cmd == APP_START_RES ||
			cmd == APP_START_RES_ASYNC ||
			cmd == APP_SEND_LAUNCH_REQUEST) {
		bundle_del(kb, AUL_K_WAIT_RESULT);
		bundle_add(kb, AUL_K_WAIT_RESULT, "1");
	}

	_noti_send("launch.prepare.end", caller_pid, target_uid, (void *)(handle->ai), kb);
	handle->prelaunch_attr = __get_prelaunch_attribute(
			handle->ai, appid, target_uid);
	handle->bg_category = __get_background_category(handle->ai);
	handle->bg_allowed = _suspend_is_allowed_background(handle->ai);
	if (handle->bg_allowed) {
		_D("[__SUSPEND__] allowed background, appid: %s, app-type: %s",
				appid, comp_type);
		bundle_del(kb, AUL_K_ALLOWED_BG);
		bundle_add(kb, AUL_K_ALLOWED_BG, "ALLOWED_BG");
	}

	_request_set_request_type(req, NULL);

	return 0;
}


static void __kill_and_cleanup_status(struct launch_s *handle, uid_t uid)
{
	app_type_e type = _app_status_get_app_type(handle->app_status);

	if (type == AT_WIDGET_APP || type == AT_WATCH_APP) {
		_W("Dead %s:%d", handle->appid, handle->pid);
		_noti_send("main.app_dead",
				handle->pid, uid, handle->app_status, NULL);
	}
	__send_to_sigkill(handle->pid, uid);
	_app_status_cleanup(handle->app_status);
	handle->app_status = NULL;
}

static int __do_starting_app(struct launch_s *handle, request_h req,
		bool *pending, bool *bg_launch)
{
	int status = -1;
	int cmd = _request_get_cmd(req);
	int caller_pid = _request_get_pid(req);
	uid_t target_uid = _request_get_target_uid(req);
	bundle *kb = _request_get_bundle(req);
	const char *pkgid;
	const char *comp_type;
	int ret;
	bool socket_exists;
	bool is_ime = false;

	pkgid = _appinfo_get_value(handle->ai, AIT_PKGID);
	comp_type = _appinfo_get_value(handle->ai, AIT_COMPTYPE);
	status = _app_status_get_status(handle->app_status);
	if (handle->pid > 0 && status != STATUS_DYING) {
		if (handle->pid == caller_pid) {
			SECURE_LOGD("caller & callee process are same. %s:%d,",
					handle->appid, handle->pid);
			return -ELOCALLAUNCH_ID;
		}

		_util_save_log("RESUMING", handle->appid);

		aul_send_app_resume_request_signal(handle->pid,
				handle->appid, pkgid, comp_type);
		_suspend_remove_timer(handle->pid);
		if (comp_type && !strcmp(comp_type, APP_TYPE_SERVICE)) {
			if (handle->bg_allowed == false) {
				__prepare_to_wake_services(handle->pid,
						target_uid);
			}
		}

		ret = __nofork_processing(cmd, handle->pid, kb, req);
		if (ret < 0) {
			_noti_send("launch.do_starting_app.relaunch.cancel", ret,
					0, NULL, NULL);
			socket_exists =
				_app_status_socket_exists(handle->app_status);
			if (ret == -ECOMM && socket_exists) {
				_E("ECOMM error, we will term the app - %s:%d",
						handle->appid, handle->pid);
				__kill_and_cleanup_status(handle, target_uid);
				return -1;
			}
		}

		_app_status_update_last_caller_pid(
				handle->app_status, caller_pid);
		_app_status_update_bg_launch(
				handle->app_status, handle->bg_launch);
		*bg_launch = _app_status_get_bg_launch(handle->app_status);

		return ret;
	}

	if (handle->pid > 0 && status == STATUS_DYING)
		__kill_and_cleanup_status(handle, target_uid);

	__set_appinfo_for_launchpad(handle->ai, kb);
	if (bundle_get_type(kb, AUL_K_SDK) != BUNDLE_TYPE_NONE) {
		aul_svc_set_loader_id(kb, PAD_LOADER_ID_DIRECT);
		handle->debug_mode = true;
	}

	_noti_send("launch.do_starting_app.start", cmd, 0, handle, kb);
	_signal_send_proc_prelaunch(handle->appid, pkgid,
			handle->prelaunch_attr, handle->bg_category);

	ret = _launchpad_launch(kb, target_uid);
	if (ret < 0) {
		_noti_send("launch.do_starting_app.cancel", ret, 0, NULL, NULL);
		return ret;
	}

	handle->pid = ret;
	*pending = true;
	*bg_launch = handle->bg_launch;

	_noti_send("launch.do_starting_app.end", 0, 0, handle, NULL);
	_suspend_add_proc(handle->pid);
	aul_send_app_launch_request_signal(handle->pid, handle->appid,
			pkgid, comp_type);
	_appinfo_get_boolean(handle->ai, AIT_IME, &is_ime);
	if (is_ime)
		_signal_send_system_service(handle->pid);

	_util_save_log("LAUNCHING", handle->appid);
	if (handle->debug_mode) {
		_W("Exclude - %s(%d)", handle->appid, handle->pid);
		aul_update_freezer_status(handle->pid, "exclude");
		return ret;
	}

	if (handle->bg_category == BACKGROUND_CATEGORY_BACKGROUND_NETWORK) {
		if (!handle->bg_allowed)
			aul_update_freezer_status(handle->pid, "include");
	}

	if (comp_type && !strcmp(comp_type, APP_TYPE_SERVICE)) {
		if (!handle->bg_allowed)
			g_idle_add(__check_service_only, GINT_TO_POINTER(ret));
	}

	return ret;
}

static int __complete_starting_app(struct launch_s *handle, request_h req)
{
	bundle *kb = _request_get_bundle(req);
	uid_t target_uid = _request_get_target_uid(req);
	int caller_pid = _request_get_pid(req);
	const char *comp_type;
	char log_status[AUL_PR_NAME];

	_noti_send("launch.complete.start", handle->pid, handle->new_process,
			(void *)(handle->ai), kb);
	comp_type = _appinfo_get_value(handle->ai, AIT_COMPTYPE);
	if (comp_type && !strcmp(comp_type, APP_TYPE_UI)) {
		if (handle->new_process) {
			__pid_of_last_launched_ui_app = handle->pid;
		}
	}

	_app_status_add_app_info(handle->ai, handle->pid, handle->is_subapp,
			target_uid, caller_pid, handle->bg_launch,
			handle->instance_id, handle->debug_mode);

	_noti_send("launch.complete.end", handle->pid, target_uid, NULL, NULL);
	snprintf(log_status, sizeof(log_status), "SUCCESS: %d", handle->pid);
	_util_save_log(log_status, handle->appid);
	return handle->pid;
}

static void __destroy_onboot_app_info(struct onboot_app_info *info)
{
	if (info == NULL)
		return;

	if (info->appid)
		free(info->appid);
	free(info);
}

static struct onboot_app_info *__create_onboot_app_info(const char *appid,
		uid_t uid)
{
	struct onboot_app_info *info;

	info = (struct onboot_app_info *)malloc(sizeof(struct onboot_app_info));
	if (!info) {
		_E("Out of memory");
		return NULL;
	}

	info->appid = strdup(appid);
	if (!info->appid) {
		_E("Out of memory");
		free(info);
		return NULL;
	}

	info->uid = uid;

	return info;
}

static gboolean __delay_start_onboot_apps(gpointer data)
{
	struct onboot_app_info *info = (struct onboot_app_info *)data;
	app_status_h app_status;
	int pid = -1;

	if (!info)
		return G_SOURCE_REMOVE;

	app_status = _app_status_find_by_appid(info->appid, info->uid);
	if (app_status)
		pid = _app_status_is_running(app_status);

	if (pid < 0)
		pid = _launch_start_app_local(info->uid, info->appid);
	_D("appid(%s), pid(%d), uid(%u)", info->appid, pid, info->uid);

	__destroy_onboot_app_info(info);

	return G_SOURCE_REMOVE;
}

static gboolean __unlock_display_state(gpointer data)
{
	_W("Unlock display state");
	_signal_send_display_unlock_state(SYSTEM_LCD_OFF, SYSTEM_SLEEP_MARGIN);
	return G_SOURCE_REMOVE;
}

static void __handle_onboot(void *data, const char *appid, struct appinfo *ai)
{
	uid_t uid = GPOINTER_TO_UINT(data);
	struct onboot_app_info *info;

	if (!__check_onboot_cond(uid, appid, ai))
		return;

	info = __create_onboot_app_info(appid, uid);
	if (!info)
		return;

	__onboot_list = g_list_append(__onboot_list, info);
}

static gboolean __load_onboot_apps(gpointer data)
{
	uid_t uid = GPOINTER_TO_UINT(data);
	struct onboot_app_info *info;
	GList *iter;
	guint interval = 0;
	guint i = 0;
	guint d = 0;

	_D("onboot uid(%d)", uid);
	_appinfo_foreach(uid, __handle_onboot, data);

	if (!__onboot_list) {
		_signal_send_display_unlock_state(SYSTEM_LCD_OFF,
				SYSTEM_SLEEP_MARGIN);
		return G_SOURCE_REMOVE;
	}

	if (g_list_length(__onboot_list) > 5) {
		d = _config_get_onboot_interval() /
			(g_list_length(__onboot_list) - 5);
	}

	iter = __onboot_list;
	while (iter) {
		info = (struct onboot_app_info *)iter->data;
		iter = g_list_next(iter);

		if (i == 6)
			interval += d;
		else if (i < 6)
			interval = _config_get_onboot_interval() * i++;

		g_timeout_add(interval, __delay_start_onboot_apps, info);
		__onboot_list = g_list_remove(__onboot_list, info);
		if (!__onboot_list) {
			g_timeout_add(interval + 5000, __unlock_display_state,
					NULL);
		}
	}

	return G_SOURCE_REMOVE;
}

int _launch_start_onboot_apps(uid_t uid)
{
	_signal_send_display_lock_state(SYSTEM_LCD_OFF,
			SYSTEM_STAY_CUR_STATE, 0);
	g_idle_add(__load_onboot_apps, GUINT_TO_POINTER(uid));

	return 0;
}

int _launch_start_app(const char *appid, request_h req, bool *pending,
		bool *bg_launch, bool new_instance)
{
	int ret;
	struct launch_s launch_data = {0,};
	int caller_pid = _request_get_pid(req);
	uid_t caller_uid = _request_get_uid(req);
	int cmd = _request_get_cmd(req);

	traceBegin(TTRACE_TAG_APPLICATION_MANAGER, "AMD:START_APP");
	_D("_launch_start_app: appid=%s caller pid=%d uid=%d",
			appid, caller_pid, caller_uid);

	ret = __prepare_starting_app(&launch_data, req, appid, new_instance);
	if (ret < 0) {
		_request_send_result(req, ret);
		traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
		_util_save_log("FAILURE", appid);
		return -1;
	}

	ret = __do_starting_app(&launch_data, req, pending, bg_launch);
	if (ret < 0) {
		_request_send_result(req, ret);
		traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
		_util_save_log("FAILURE", appid);
		return -1;
	}

	if (cmd == APP_START_ASYNC || cmd == APP_START_RES_ASYNC)
		_request_send_result(req, ret);

	ret = __complete_starting_app(&launch_data, req);
	traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
	if (ret < 0)
		_util_save_log("FAILURE", appid);

	return ret;
}

int _launch_context_get_pid(launch_h h)
{
	struct launch_s *context = h;

	if (!context)
		return -1;

	return h->pid;
}

int _launch_context_set_pid(launch_h h, int pid)
{
	struct launch_s *context = h;

	if (!context)
		return -1;

	h->pid = pid;

	return 0;
}

const char *_launch_context_get_appid(launch_h h)
{
	struct launch_s *context = h;

	if (!context)
		return NULL;

	return h->appid;
}

bool _launch_context_is_new_instance(launch_h h)
{
	struct launch_s *context = h;

	if (!context)
		return false;

	return h->new_instance;
}

int _launch_context_set_subapp(launch_h h, bool is_subapp)
{
	struct launch_s *context = h;

	if (!context)
		return -1;

	h->is_subapp = is_subapp;

	return 0;
}

int _launch_context_set_app_status(launch_h h, app_status_h status)
{
	struct launch_s *context = h;

	if (!context)
		return -1;

	h->app_status = status;

	return 0;
}

const char *_launch_context_get_instance_id(launch_h h)
{
	struct launch_s *context = h;

	if (!context)
		return NULL;

	return h->instance_id;
}

bool _launch_context_is_subapp(launch_h h)
{
	struct launch_s *context = h;

	if (!context)
		return false;

	return h->is_subapp;
}

bool _launch_context_is_bg_launch(launch_h h)
{
	struct launch_s *context = h;

	if (!context)
		return false;

	return h->bg_launch;
}

const struct appinfo *_launch_context_get_appinfo(launch_h h)
{
	struct launch_s *context = h;

	if (!context)
		return NULL;

	return h->ai;
}

void _launch_set_mode(launch_mode_e mode)
{
	if (mode > LAUNCH_MODE_BLOCK) {
		_E("Invalid mode: %d", mode);
		return;
	}

	__launch_mode = mode;
	_W("Mode: %d", __launch_mode);
}
