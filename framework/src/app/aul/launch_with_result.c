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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <glib.h>
// #include <gio/gio.h>
// #include <bundle_internal.h>

#include "aul.h"
#include "aul_api.h"
#include "aul_sock.h"
#include "aul_util.h"
#include "aul_svc.h"
#include "aul_error.h"
#include "launch.h"

typedef struct _app_resultcb_info_t {
	// GIOChannel *io;
	int launched_pid;
	char *seq_num;
	void (*reply_cb)(bundle *b, int is_cancel, void *data);
	void (*error_cb)(int result, void *data);
	void *user_data;
	void (*caller_cb) (int launched_pid, void *data);
	void *caller_data;
	int cmd;
	bundle *b;
} app_resultcb_info_t;

static pthread_mutex_t __aul_mutex = PTHREAD_MUTEX_INITIALIZER;
static GList *__resultcb_list;

static int __rand(int n)
{
	unsigned int seed = time(NULL) + n;
	return rand_r(&seed);
}

static char *__gen_seq_num(void)
{
	static int num;
	char buf[MAX_LOCAL_BUFSZ];

	num++;
	snprintf(buf, sizeof(buf), "%d@%d", __rand(num), num);

	return strdup(buf);
}

static void __add_resultcb(app_resultcb_info_t *info)
{
	if (!info)
		return;

	pthread_mutex_lock(&__aul_mutex);
	__resultcb_list = g_list_prepend(__resultcb_list, info);
	pthread_mutex_unlock(&__aul_mutex);
}

static void __remove_resultcb(app_resultcb_info_t *info)
{
	if (!info)
		return;

	pthread_mutex_lock(&__aul_mutex);
	__resultcb_list = g_list_remove(__resultcb_list, info);
	pthread_mutex_unlock(&__aul_mutex);
}

static app_resultcb_info_t *__find_resultcb(const char *seq_num)
{
	app_resultcb_info_t *info;
	GList *iter;

	pthread_mutex_lock(&__aul_mutex);
	iter = __resultcb_list;
	while (iter) {
		info = (app_resultcb_info_t *)iter->data;
		if (!strcmp(info->seq_num, seq_num)) {
			pthread_mutex_unlock(&__aul_mutex);
			return info;
		}
		iter = g_list_next(iter);
	}
	pthread_mutex_unlock(&__aul_mutex);

	return NULL;
}

static void __destroy_resultcb(app_resultcb_info_t *info)
{
	if (!info)
		return;

	if (info->b)
		bundle_free(info->b);

	// if (info->io)
	// 	g_io_channel_unref(info->io);

	if (info->seq_num)
		free(info->seq_num);

	free(info);
}

static app_resultcb_info_t *__create_resultcb(int pid,
		const char *seq_num,
		void (*reply_cb)(bundle *, int, void *),
		void (*error_cb)(int, void *), void *data)
{
	app_resultcb_info_t *info;

	info = calloc(1, sizeof(app_resultcb_info_t));
	if (info == NULL) {
		_E("Out of memory");
		return NULL;
	}

	info->seq_num = strdup(seq_num);
	if (info->seq_num == NULL) {
		_E("Failed to duplicate seq num");
		free(info);
		return NULL;
	}

	info->launched_pid = pid;
	info->reply_cb = reply_cb;
	info->error_cb = error_cb;
	info->user_data = data;

	return info;
}

/**
 * call result callback function
 * run in caller
 */
static int __call_app_result_callback(bundle *kb, int is_cancel,
		int launched_pid)
{
	app_resultcb_info_t *new_info;
	app_resultcb_info_t *info;
	const char *fwdpid_str;
	const char *num_str;

	if (kb == NULL) {
		_E("Invalid parameter");
		return -1;
	}

	num_str = bundle_get_val(kb, AUL_K_SEQ_NUM);
	if (num_str == NULL) {
		_E("seq num is null");
		return -1;
	}

	info = __find_resultcb(num_str);
	if (!info || launched_pid < 0) {
		_E("reject by pid - wait pid = %d, recvd pid = %d",
				getpid(), launched_pid);
		return -1;
	}

	if (info->reply_cb == NULL) {
		_E("Callback function is null");
		return -1;
	}

	fwdpid_str = bundle_get_val(kb, AUL_K_FWD_CALLEE_PID);
	/* In case of aul_forward_app, update the callback data */
	if (is_cancel == 1 && fwdpid_str) {
		launched_pid = atoi(fwdpid_str);
		new_info = __create_resultcb(launched_pid, num_str,
				info->reply_cb, info->error_cb,
				info->user_data);
		if (new_info)
			__add_resultcb(new_info);

		if (info->caller_cb) {
			info->caller_cb(launched_pid, info->caller_data);
			info->caller_cb = NULL;
		}

		if (!info->error_cb) {
			__remove_resultcb(info);
			__destroy_resultcb(info);
		}

		_D("change callback, fwd pid: %d", launched_pid);

		goto end;
	}

	info->reply_cb(kb, is_cancel, info->user_data);
	info->reply_cb = NULL;

	if (!info->error_cb) {
		__remove_resultcb(info);
		__destroy_resultcb(info);
	}

end:
	return 0;
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

int app_result(int cmd, bundle *kb, int launched_pid)
{
	switch (cmd) {
	case APP_RESULT:
		__call_app_result_callback(kb, 0, launched_pid);
		break;
	case APP_CANCEL:
		__call_app_result_callback(kb, 1, launched_pid);
		break;
	}

	return 0;
}

static int __launch_app_with_result(int cmd, const char *appid, bundle *kb,
		void (*callback)(bundle *, int, void *), void *data, uid_t uid)
{
	int ret;
	char *seq_num;
	app_resultcb_info_t *info;

	if (!aul_is_initialized()) {
		if (aul_launch_init(NULL, NULL) < 0)
			return AUL_R_ENOINIT;
	}

	if (appid == NULL || callback == NULL || kb == NULL)
		return AUL_R_EINVAL;

	seq_num = __gen_seq_num();
	if (seq_num == NULL) {
		_E("Out of memory");
		return AUL_R_ERROR;
	}

	bundle_del(kb, AUL_K_SEQ_NUM);
	bundle_add(kb, AUL_K_SEQ_NUM, seq_num);

	info = __create_resultcb(-1, seq_num, callback, NULL, data);
	if (info)
		__add_resultcb(info);
	free(seq_num);

	ret = app_request_to_launchpad_for_uid(cmd, appid, kb, uid);
	if (ret > 0) {
		if (info)
			info->launched_pid = ret;
	} else {
		__remove_resultcb(info);
		__destroy_resultcb(info);
	}

	return ret;
}

API int aul_launch_app_with_result(const char *pkgname, bundle *kb,
			       void (*cbfunc) (bundle *, int, void *),
			       void *data)
{
	return __launch_app_with_result(APP_START_RES, pkgname, kb, cbfunc,
			data, getuid());
}

API int aul_launch_app_with_result_for_uid(const char *pkgname, bundle *kb,
		void (*cbfunc) (bundle *, int, void *), void *data, uid_t uid)
{
	return __launch_app_with_result(APP_START_RES, pkgname, kb, cbfunc,
			data, uid);
}

void __iterate(const char *key, const char *val, void *data)
{
	static int i = 0;
	_D("%d %s %s", i++, key, val);
}

static int __set_caller_info(bundle *kb)
{
	const char *caller_pid;
	const char *caller_uid;

	caller_pid = bundle_get_val(kb, AUL_K_CALLER_PID);
	if (caller_pid == NULL) {
		_E("Failed to get caller pid");
		return AUL_R_EINVAL;
	}

	caller_uid = bundle_get_val(kb, AUL_K_CALLER_UID);
	if (caller_uid == NULL) {
		_E("Failed to get caller uid");
		return AUL_R_EINVAL;
	}

	bundle_del(kb, AUL_K_ORG_CALLER_PID);
	bundle_add(kb, AUL_K_ORG_CALLER_PID, caller_pid);
	bundle_del(kb, AUL_K_ORG_CALLER_UID);
	bundle_add(kb, AUL_K_ORG_CALLER_UID, caller_uid);

	return AUL_R_OK;
}

API int aul_forward_app(const char* pkgname, bundle *kb)
{
	int ret;
	bundle *dupb;
	bundle *outb;
	char tmp_pid[MAX_PID_STR_BUFSZ];

	if (pkgname == NULL || kb == NULL)
		return AUL_R_EINVAL;

	if (__set_caller_info(kb) < 0)
		return AUL_R_EINVAL;

	bundle_del(kb, AUL_SVC_K_CAN_BE_LEADER);
	bundle_del(kb, AUL_SVC_K_REROUTE);
	bundle_del(kb, AUL_SVC_K_RECYCLE);

	dupb = bundle_dup(kb);
	if (dupb == NULL) {
		_E("bundle duplicate fail");
		return AUL_R_EINVAL;
	}

	if (bundle_get_val(kb, AUL_K_WAIT_RESULT) != NULL) {
		ret = app_request_to_launchpad(APP_START_RES, pkgname, kb);
		if (ret < 0)
			goto end;
	} else {
		ret = app_request_to_launchpad(APP_START, pkgname, kb);
		goto end;
	}

	/* bundle_iterate(dupb, __iterate, NULL); */

	snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", ret);

	ret = aul_create_result_bundle(dupb, &outb);
	if (ret < 0)
		goto end;

	bundle_del(outb, AUL_K_FWD_CALLEE_PID);
	bundle_add(outb, AUL_K_FWD_CALLEE_PID, tmp_pid);

	/* bundle_iterate(outb, __iterate, NULL); */

	ret = aul_send_result(outb, 1);

	bundle_free(outb);
end:
	bundle_free(dupb);

	return ret;
}


API int aul_create_result_bundle(bundle *inb, bundle **outb)
{
	const char *pid_str;
	const char *num_str;
	const char *uid_str;

	*outb = NULL;

	if (inb == NULL) {
		_E("return msg create fail");
		return AUL_R_EINVAL;
	}

	*outb = bundle_create();
	if (*outb == NULL) {
		_E("return msg create fail");
		return AUL_R_ERROR;
	}

	if (bundle_get_val(inb, AUL_K_WAIT_RESULT) != NULL) {
		bundle_add(*outb, AUL_K_SEND_RESULT, "1");
		_D("original msg is msg with result");
	} else {
		_D("original msg is not msg with result");
	}

	uid_str = bundle_get_val(inb, AUL_K_ORG_CALLER_UID);
	if (uid_str == NULL)
		uid_str = bundle_get_val(inb, AUL_K_CALLER_UID);

	if (uid_str == NULL) {
		_E("Failed to find caller uid");
		bundle_free(*outb);
		*outb = NULL;
		return AUL_R_EINVAL;
	}
	bundle_add(*outb, AUL_K_ORG_CALLER_UID, uid_str);

	pid_str = bundle_get_val(inb, AUL_K_ORG_CALLER_PID);
	if (pid_str) {
		bundle_add(*outb, AUL_K_ORG_CALLER_PID, pid_str);
		goto end;
	}

	pid_str = bundle_get_val(inb, AUL_K_CALLER_PID);
	if (pid_str == NULL) {
		_E("original msg does not have caller pid");
		bundle_free(*outb);
		*outb = NULL;
		return AUL_R_EINVAL;
	}
	bundle_add(*outb, AUL_K_CALLER_PID, pid_str);

end:
	num_str = bundle_get_val(inb, AUL_K_SEQ_NUM);
	if (num_str == NULL) {
		_E("original msg does not have seq num");
		bundle_free(*outb);
		*outb = NULL;
		return AUL_R_ECANCELED;
	}
	bundle_add(*outb, AUL_K_SEQ_NUM, num_str);

	return AUL_R_OK;
}

int aul_send_result(bundle *kb, int is_cancel)
{
	int pid;
	int ret;
	int callee_pid;
	int callee_pgid;
	char callee_appid[256];
	char tmp_pid[MAX_PID_STR_BUFSZ];

	if ((pid = __get_caller_pid(kb)) < 0)
		return AUL_R_EINVAL;

	_D("caller pid : %d", pid);

	if (bundle_get_val(kb, AUL_K_SEND_RESULT) == NULL) {
		_D("original msg is not msg with result");
		return AUL_R_OK;
	}

	callee_pid = getpid();
	callee_pgid = getpgid(callee_pid);
	snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", callee_pgid);
	bundle_add(kb, AUL_K_CALLEE_PID, tmp_pid);

	ret = aul_app_get_appid_bypid(callee_pid, callee_appid, sizeof(callee_appid));
	if (ret == 0)
		bundle_add(kb, AUL_K_CALLEE_APPID, callee_appid);
	else
		_W("fail(%d) to get callee appid by pid", ret);

	ret = app_send_cmd_with_noreply(AUL_UTIL_PID,
			(is_cancel == 1) ? APP_CANCEL : APP_RESULT, kb);
	_D("app_send_cmd_with_noreply : %d", ret);

	return ret;
}

API int aul_subapp_terminate_request_pid(int pid)
{
	char pid_str[MAX_PID_STR_BUFSZ];
	int ret;
	app_resultcb_info_t *info;
	GList *iter;

	if (pid <= 0)
		return AUL_R_EINVAL;

	pthread_mutex_lock(&__aul_mutex);
	iter = __resultcb_list;
	while (iter) {
		info = (app_resultcb_info_t *)iter->data;
		iter = g_list_next(iter);
		if (info->launched_pid == pid && !info->error_cb) {
			__resultcb_list = g_list_remove(
					__resultcb_list, info);
			__destroy_resultcb(info);
		}
	}
	pthread_mutex_unlock(&__aul_mutex);

	snprintf(pid_str, MAX_PID_STR_BUFSZ, "%d", pid);
	ret = app_request_to_launchpad(APP_TERM_REQ_BY_PID, pid_str, NULL);
	return ret;
}

API int aul_add_caller_cb(int pid, void (*caller_cb)(int, void *),
		void *data)
{
	app_resultcb_info_t *info;
	GList *iter;

	if (pid <= 0)
		return AUL_R_EINVAL;

	pthread_mutex_lock(&__aul_mutex);
	iter = __resultcb_list;
	while (iter) {
		info = (app_resultcb_info_t *)iter->data;
		if (info->launched_pid == pid &&
				info->caller_cb == NULL) {
			info->caller_cb = caller_cb;
			info->caller_data = data;
			pthread_mutex_unlock(&__aul_mutex);
			return AUL_R_OK;
		}
		iter = g_list_next(iter);
	}
	pthread_mutex_unlock(&__aul_mutex);

	return AUL_R_ERROR;
}

API int aul_remove_caller_cb(int pid, void *data)
{
	app_resultcb_info_t *info;
	GList *iter;

	if (pid <= 0)
		return AUL_R_EINVAL;

	pthread_mutex_lock(&__aul_mutex);
	iter = __resultcb_list;
	while (iter) {
		info = (app_resultcb_info_t *)iter->data;
		if (info->launched_pid == pid &&
				info->caller_data == data) {
			info->caller_cb = NULL;
			info->caller_data = NULL;
			pthread_mutex_unlock(&__aul_mutex);
			return AUL_R_OK;
		}
		iter = g_list_next(iter);
	}
	pthread_mutex_unlock(&__aul_mutex);

	return AUL_R_ERROR;
}

static void __invoke_caller_cb(gpointer data)
{
	app_resultcb_info_t *info = (app_resultcb_info_t *)data;

	if (info->caller_cb)
		info->caller_cb(info->launched_pid, info->caller_data);

	__destroy_resultcb(info);

	// return G_SOURCE_REMOVE;
}

API int aul_invoke_caller_cb(void *data)
{
	app_resultcb_info_t *info;
	app_resultcb_info_t *new_info;
	GList *iter;

	pthread_mutex_lock(&__aul_mutex);
	iter = __resultcb_list;
	while (iter) {
		info = (app_resultcb_info_t *)iter->data;
		if (info->caller_data == data) {
			/* Duplicate resultcb info */
			new_info = __create_resultcb(info->launched_pid,
					info->seq_num,
					info->reply_cb,
					info->error_cb,
					info->user_data);
			if (!new_info)
				break;

			new_info->caller_cb = info->caller_cb;
			new_info->caller_data = info->caller_data;
			eventloop_thread_safe_function_call(__invoke_caller_cb, new_info);

			break;
		}
		iter = g_list_next(iter);

	}
	pthread_mutex_unlock(&__aul_mutex);

	return 0;
}

API int aul_launch_app_with_result_async(const char *appid, bundle *b,
		void (*callback)(bundle *, int, void *), void *data)
{
	return __launch_app_with_result(APP_START_RES_ASYNC, appid, b, callback,
			data, getuid());
}

API int aul_launch_app_with_result_async_for_uid(const char *appid, bundle *b,
		void (*callback)(bundle *, int, void *), void *data, uid_t uid)
{
	return __launch_app_with_result(APP_START_RES_ASYNC, appid, b, callback,
			data, uid);
}

// static gboolean __aul_error_handler(GIOChannel *io,
// 		GIOCondition cond, gpointer user_data)
// {
// 	int fd = g_io_channel_unix_get_fd(io);
// 	app_resultcb_info_t *info = (app_resultcb_info_t *)user_data;
// 	int res;

// 	if (!info) {
// 		_E("Critical error!");
// 		close(fd);
// 		return G_SOURCE_REMOVE;
// 	}

// 	res = aul_sock_recv_result_with_fd(fd);
// 	if (res < 1) {
// 		res = aul_error_convert(res);
// 		if (res == AUL_R_LOCAL) {
// 			res = app_request_local(info->cmd, info->b);
// 			if (info->b) {
// 				bundle_free(info->b);
// 				info->b = NULL;
// 			}
// 		}
// 	}

// 	_W("Sequence(%s), result(%d)", info->seq_num, res);

// 	if (info->error_cb) {
// 		info->error_cb(res, info->user_data);
// 		info->error_cb = NULL;
// 	}

// 	if (res > 0 && info->reply_cb) {
// 		info->launched_pid = res;
// 	} else {
// 		__remove_resultcb(info);
// 		__destroy_resultcb(info);
// 	}
// 	close(fd);

// 	return G_SOURCE_REMOVE;
// }

static int __resultcb_add_watch(int fd, app_resultcb_info_t *info)
{
	// GIOCondition cond = G_IO_IN | G_IO_PRI | G_IO_ERR | G_IO_HUP;
	// guint source;

	// info->io = g_io_channel_unix_new(fd);
	// if (!info->io) {
	// 	_E("Failed to create gio channel");
	// 	return -1;
	// }

	// source = g_io_add_watch(info->io, cond, __aul_error_handler, info);
	// if (!source) {
	// 	_E("Failed to add gio watch");
	// 	return -1;
	// }
	// g_io_channel_set_close_on_unref(info->io, TRUE);

	return 0;
}

API int aul_send_launch_request_for_uid(const char *appid, bundle *b, uid_t uid,
		void (*reply_cb)(bundle *b, int, void *),
		void (*error_cb)(int, void *),
		void *user_data)
{
	app_resultcb_info_t *info;
	char *seq_num;
	int fd;

	if (!aul_is_initialized()) {
		if (aul_launch_init(NULL, NULL) < 0) {
			_E("Failed to initialize aul launch");
			return AUL_R_ENOINIT;
		}
	}

	if (!appid || !b || !error_cb) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	seq_num = __gen_seq_num();
	if (!seq_num) {
		_E("Out of memory");
		return AUL_R_ERROR;
	}

	bundle_del(b, AUL_K_SEQ_NUM);
	bundle_add(b, AUL_K_SEQ_NUM, seq_num);

	info = __create_resultcb(-1, seq_num, reply_cb, error_cb, user_data);
	free(seq_num);
	if (!info) {
		_E("Failed to create resultcb info");
		return AUL_R_ERROR;
	} else {
		__add_resultcb(info);
	}

	fd = app_request_to_launchpad_for_uid(APP_SEND_LAUNCH_REQUEST,
			appid, b, uid);
	if (fd < 0/* || fd > sysconf(_SC_OPEN_MAX)*/) {
		_E("Failed to send launch request. appid(%s), result(%d)",
				appid, fd);
		__remove_resultcb(info);
		__destroy_resultcb(info);
		return AUL_R_ECOMM;
	}

	if (__resultcb_add_watch(fd, info) < 0) {
		_E("Failed to add resultcb watch");
		__remove_resultcb(info);
		__destroy_resultcb(info);
		close(fd);
		return AUL_R_ERROR;
	}

	info->cmd = APP_SEND_LAUNCH_REQUEST;
	info->b = bundle_dup(b);

	return AUL_R_OK;
}
