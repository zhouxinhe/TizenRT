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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <poll.h>
#include <ctype.h>
#include <glib.h>
#include <gio/gio.h>
#include <aul.h>
#include <aul_cmd.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <tzplatform_config.h>
#include <systemd/sd-login.h>
#include <aul_sock.h>
#include <aul_svc.h>
#include <aul_app_com.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_request.h"
#include "amd_app_status.h"
#include "amd_cynara.h"
#include "amd_socket.h"
#include "aul_svc_priv_key.h"
#include "amd_signal.h"
#include "amd_login_monitor.h"
#include "amd_noti.h"

#define PENDING_REQUEST_TIMEOUT 5000 /* msec */
#define SYSTEM_REQUEST_TIMEOUT 90000 /* msec */
#define PENDING_MESSAGE_MAX_CNT 100

static int amd_fd;
static GIOChannel *amd_io;
static guint amd_wid;
static GHashTable *pending_table;
static GHashTable *__dispatch_table;

struct pending_item {
	int pid;
	guint timer;
	GList *pending_list;
	GList *reply_list;
};

struct request_s {
	GTimeVal start;
	guint timer;
	int cmd;
	int clifd;
	pid_t pid;
	pid_t t_pid;
	uid_t uid;
	uid_t t_uid;
	bundle *kb;
	int len;
	int opt;
	bool critical;
	unsigned char data[1];
};

struct extra_info {
	char *key;
	void *extra;
	void (*free_cb)(void *data);
};

struct reply_info {
	guint timer;
	pid_t pid;
	int result;
	int cmd;
	int clifd;
	GList *extra_list;
};

static gboolean __timeout_pending_item(gpointer user_data);
static gboolean __dispatch_request(gpointer data);
static gboolean __timeout_request(gpointer data);
static int __add_request_on_pending_list(request_h req);

static void __free_extra_info(gpointer data)
{
	struct extra_info *info = data;

	if (info->free_cb)
		info->free_cb(info->extra);
	free(info->key);
	free(info);
}

static void __free_reply_info(gpointer data)
{
	struct reply_info *reply = (struct reply_info *)data;

	if (reply == NULL)
		return;

	if (reply->extra_list)
		g_list_free_full(reply->extra_list, __free_extra_info);
	if (reply->clifd)
		close(reply->clifd);
	if (reply->timer)
		g_source_remove(reply->timer);
	free(reply);
}

static gboolean __timeout_reply(gpointer data)
{
	struct reply_info *reply = (struct reply_info *)data;

	if (reply == NULL)
		return FALSE;

	_request_reply_remove(reply->pid, reply);
	_send_result_to_client(reply->clifd, reply->result);
	reply->clifd = 0;
	reply->timer = 0;
	__free_reply_info(reply);

	return FALSE;
}

static struct reply_info *__create_reply_info(guint interval, pid_t pid,
		int result, int cmd, int clifd)
{
	struct reply_info *reply;

	reply = malloc(sizeof(struct reply_info));
	if (reply == NULL) {
		_E("Out of memory");
		return NULL;
	}

	reply->pid = pid;
	reply->result = result;
	reply->cmd = cmd;
	reply->clifd = clifd;
	reply->timer = g_timeout_add(interval, __timeout_reply, reply);
	reply->extra_list = NULL;

	return reply;
}

static void __free_request(gpointer data)
{
	request_h req = (request_h)data;

	if (req == NULL)
		return;

	if (req->clifd)
		close(req->clifd);
	if (req->timer)
		g_source_remove(req->timer);
	if (req->kb)
		bundle_free(req->kb);

	free(req);
}

static void __free_pending_item(gpointer user_data)
{
	struct pending_item *item = (struct pending_item *)user_data;

	if (item == NULL)
		return;

	if (item->reply_list)
		g_list_free_full(item->reply_list, __free_reply_info);
	if (item->pending_list)
		g_list_free_full(item->pending_list, __free_request);
	if (g_main_context_find_source_by_user_data(NULL, item))
		g_source_remove(item->timer);
	free(item);
}

static void __timeout_pending_reply(gpointer data, gpointer user_data)
{
	struct reply_info *reply = (struct reply_info *)data;

	if (reply == NULL)
		return;

	_send_result_to_client(reply->clifd, reply->result);
	reply->clifd = 0;
}

static void __timeout_pending_request(gpointer data, gpointer user_data)
{
	request_h req = (request_h)data;

	if (req == NULL)
		return;

	_request_send_result(req, -EAGAIN);
}

static gboolean __timeout_pending_item(gpointer user_data)
{
	struct pending_item *item = (struct pending_item *)user_data;

	if (item == NULL)
		return FALSE;

	g_list_foreach(item->reply_list, __timeout_pending_reply, NULL);
	g_list_foreach(item->pending_list, __timeout_pending_request, NULL);
	g_hash_table_remove(pending_table, GINT_TO_POINTER(item->pid));

	return FALSE;
}

static void __flush_pending_reply_list(GList **reply_list, bool is_dead)
{
	GList *iter;
	struct reply_info *reply;

	if (reply_list == NULL)
		return;

	iter = g_list_first(*reply_list);
	while (iter) {
		reply = (struct reply_info *)iter->data;
		iter = g_list_next(iter);
		if (reply == NULL)
			continue;

		if (reply->cmd == APP_TERM_BY_PID_SYNC_WITHOUT_RESTART ||
				reply->cmd == APP_TERM_BY_PID_SYNC) {
			if (!is_dead)
				continue;

			reply->result = 0;
		}

		*reply_list = g_list_remove(*reply_list, reply);
		_send_result_to_client(reply->clifd, reply->result);
		reply->clifd = 0;
		__free_reply_info(reply);
	}
}

static void __flush_pending_request_list(GList **pending_list)
{
	GList *iter;
	request_h req;

	if (pending_list == NULL)
		return;

	iter = g_list_first(*pending_list);
	while (iter) {
		req = (request_h)iter->data;
		iter = g_list_next(iter);
		if (req == NULL)
			continue;

		*pending_list = g_list_remove(*pending_list, req);
		if (req->timer) {
			g_source_remove(req->timer);
			req->timer = 0;
		}
		g_idle_add(__dispatch_request, req);
	}
}

int _request_flush_pending_request(int pid)
{
	struct pending_item *item;

	item = (struct pending_item *)g_hash_table_lookup(pending_table,
			GINT_TO_POINTER(pid));
	if (item == NULL)
		return -1;

	__flush_pending_reply_list(&item->reply_list, true);
	__timeout_pending_item((gpointer)item);

	return 0;
}

int _request_reply_for_pending_request(int pid)
{
	struct pending_item *item;

	_app_status_publish_status(pid, STATUS_LAUNCHING);

	item = (struct pending_item *)g_hash_table_lookup(pending_table,
			GINT_TO_POINTER(pid));
	if (item == NULL)
		return -1;

	__flush_pending_reply_list(&item->reply_list, false);
	__flush_pending_request_list(&item->pending_list);

	return 0;
}

static GTimeVal __get_start_time(request_h req)
{
	int r;
	GTimeVal start;
	const char *start_time = NULL;

	if (req->kb)
		start_time = bundle_get_val(req->kb, AUL_K_STARTTIME);

	if (start_time) {
		r = sscanf(start_time, "%ld/%ld",
				&start.tv_sec, &start.tv_usec);
		if (r != 2)
			g_get_current_time(&start);
	} else {
		g_get_current_time(&start);
	}

	return start;
}

static request_h __get_request(int clifd, app_pkt_t *pkt,
		struct ucred cr)
{
	request_h req;
	const char *target_uid;

	req = (request_h)malloc(sizeof(struct request_s) + pkt->len);
	if (req == NULL)
		return NULL;

	req->timer = 0;
	req->clifd = clifd;
	req->pid = cr.pid;
	req->t_pid = 0;
	req->uid = cr.uid;
	req->cmd = pkt->cmd;
	req->len = pkt->len;
	req->opt = pkt->opt;
	req->critical = false;
	memcpy(req->data, pkt->data, pkt->len + 1);

	if (pkt->opt & AUL_SOCK_BUNDLE) {
		req->kb = bundle_decode(pkt->data, pkt->len);
		if (req->kb == NULL) {
			free(req);
			return NULL;
		}

		target_uid = bundle_get_val(req->kb, AUL_K_TARGET_UID);
		if (target_uid && isdigit(target_uid[0]))
			req->t_uid = atoi(target_uid);
		else
			req->t_uid = cr.uid;
	} else {
		req->kb = NULL;
		req->t_uid = cr.uid;
	}

	req->start = __get_start_time(req);

	return req;
}

static gboolean __timeout_request(gpointer data)
{
	request_h req = (request_h)data;
	struct pending_item *item;
	app_status_h app_status;

	if (req == NULL)
		return FALSE;

	item = g_hash_table_lookup(pending_table, GINT_TO_POINTER(req->t_pid));
	if (item)
		item->pending_list = g_list_remove(item->pending_list, req);

	if (req->clifd)
		_request_send_result(req, -EAGAIN);
	req->timer = 0;

	if (req->critical) {
		_E("App is not responding");
		app_status = _app_status_find(req->t_pid);
		if (app_status)
			_app_status_update_status(app_status, STATUS_DYING, false, true);
	}

	__free_request(req);

	return FALSE;
}

static app_status_h __get_app_status(request_h req, const char *appid)
{
	int pid;
	app_status_h app_status;
	int status;
	struct appinfo *ai;
	const char *comp_type;

	switch (req->cmd) {
	case APP_RESUME_BY_PID:
	case APP_TERM_BY_PID:
	case APP_TERM_BY_PID_WITHOUT_RESTART:
	case APP_KILL_BY_PID:
	case APP_TERM_REQ_BY_PID:
	case APP_TERM_BY_PID_ASYNC:
	case APP_TERM_BGAPP_BY_PID:
	case APP_PAUSE_BY_PID:
	case APP_TERM_BY_PID_SYNC:
	case APP_TERM_BY_PID_SYNC_WITHOUT_RESTART:
		/* get pid */
		pid = atoi(appid);
		app_status = _app_status_find(pid);
		break;
	case APP_START_ASYNC:
	case APP_START_RES_ASYNC:
		ai = _appinfo_find(_request_get_target_uid(req), appid);
		comp_type = _appinfo_get_value(ai, AIT_COMPTYPE);
		if (comp_type && (strcmp(comp_type, APP_TYPE_WIDGET) == 0 ||
				strcmp(comp_type, APP_TYPE_WATCH) == 0)) {
			app_status = _app_status_find_with_org_caller(appid,
					_request_get_target_uid(req),
					_request_get_pid(req));
		} else {
			app_status = _app_status_find_by_appid(appid,
					_request_get_target_uid(req));
		}
		break;
	default:
		app_status = _app_status_find_by_appid(appid,
				_request_get_target_uid(req));
		break;
	}

	if (app_status == NULL)
		return NULL;

	status = _app_status_get_status(app_status);
	if (status == STATUS_DYING)
		return NULL;

	return app_status;
}

static int __check_request(request_h req)
{
	int pid;
	struct pending_item *item;
	app_status_h app_status;
	const char *appid;

	if (req->opt & AUL_SOCK_NOREPLY)
		close(_request_remove_fd(req));

	if ((req->opt & AUL_SOCK_QUEUE) == 0)
		return 0;

	if (req->kb == NULL)
		return -1;

	appid = bundle_get_val(req->kb, AUL_K_APPID);
	if (appid == NULL)
		return -1;

	app_status = __get_app_status(req, appid);
	if (app_status == NULL)
		return 0;

	if (_app_status_socket_exists(app_status))
		return 0;

	pid = _app_status_get_pid(app_status);
	item = g_hash_table_lookup(pending_table, GINT_TO_POINTER(pid));
	if (item == NULL)
		return 0;

	if (!_app_status_is_starting(app_status)) {
		req->t_pid = pid;
		_W("%s(%d) is waiting to be started.", appid, pid);
		req->critical = true;
		req->timer = g_timeout_add(PENDING_REQUEST_TIMEOUT,
				__timeout_request, req);
	}

	item->pending_list = g_list_append(item->pending_list, req);

	return 1;
}

static int __check_target_user(request_h req)
{
	int r;
	uid_t *uids;
	int i;
	uid_state state;

	if (req->t_uid >= REGULAR_UID_MIN) {
		state = _login_monitor_get_uid_state(req->t_uid);
		if (state == UID_STATE_ONLINE || state == UID_STATE_ACTIVE)
			return 0;

		if (state == UID_STATE_OPENING)
			return 1;

		return -1;
	}

	r = _login_monitor_get_uids(&uids);
	if (r <= 0)
		return -1;

	for (i = 0; i < r; i++) {
		state = _login_monitor_get_uid_state(uids[i]);
		if (state == UID_STATE_ONLINE || state == UID_STATE_ACTIVE) {
			req->t_uid = uids[i];
			break;
		}
	}
	free(uids);

	if (req->t_uid < REGULAR_UID_MIN)
		return -1;

	return 0;
}

static gboolean __dispatch_request(gpointer data)
{
	request_h req = (request_h)data;
	request_cmd_dispatch *dispatcher;

	if (req == NULL)
		return FALSE;

	_I("cmd(%s:%d), caller_pid(%d), caller_uid(%u), clifd(%d)",
			aul_cmd_convert_to_string(req->cmd),
			req->cmd, req->pid, req->uid, req->clifd);
	dispatcher = g_hash_table_lookup(__dispatch_table,
			GINT_TO_POINTER(req->cmd));
	if (dispatcher) {
		if (dispatcher->callback(req) != 0) {
			_E("callback returns FALSE : cmd(%s:%d)",
					aul_cmd_convert_to_string(req->cmd),
					req->cmd);
		}
	} else {
		_E("Invalid request or not supported command(%d). caller(%d)",
				req->cmd, req->pid);
	}

	__free_request(req);

	return FALSE;
}

static guint __get_pending_interval(GTimeVal *start, GTimeVal *end)
{
	guint sec;
	guint usec;
	guint interval;

	sec = (end->tv_sec - start->tv_sec) * 1000;
	usec = (end->tv_usec - start->tv_usec) / 1000;
	interval = sec + usec;
	if (interval >= PENDING_REQUEST_TIMEOUT)
		return 0;

	return PENDING_REQUEST_TIMEOUT - interval;
}

int _request_reply_reset_pending_timer(request_h req, unsigned int interval, int pid)
{
	struct pending_item *item;
	GTimeVal end;

	item = g_hash_table_lookup(pending_table, GINT_TO_POINTER(pid));
	if (item == NULL) {
		_W("pending item doesn't exist - pid(%d)", pid);
		return -1;
	}

	if (item->timer)
		g_source_remove(item->timer);

	if (interval <= 0) {
		g_get_current_time(&end);
		interval = __get_pending_interval(_request_get_start_time(req), &end);
	}

	item->timer = g_timeout_add(interval, __timeout_pending_item, item);

	return 0;
}

int _request_reply_append(int pid, void *reply)
{
	struct pending_item *item;

	item = g_hash_table_lookup(pending_table, GINT_TO_POINTER(pid));
	if (item == NULL) {
		item = calloc(1, sizeof(struct pending_item));
		if (item == NULL) {
			_E("Out of memory");
			return -1;
		}
		item->pid = pid;
		g_hash_table_insert(pending_table, GINT_TO_POINTER(pid),
				item);
	} else {
		if (item->timer) {
			g_source_remove(item->timer);
			item->timer = 0;
		}
	}

	item->reply_list = g_list_append(item->reply_list, reply);

	return 0;
}

int _request_reply_remove(int pid, void *reply)
{
	struct pending_item *item;

	item = g_hash_table_lookup(pending_table, GINT_TO_POINTER(pid));
	if (item)
		item->reply_list = g_list_remove(item->reply_list, reply);

	return 0;
}

request_reply_h _request_reply_create(request_h req, pid_t pid, int result, int cmd)
{
	request_reply_h reply;
	unsigned int interval;
	GTimeVal end;
	int clifd = _request_remove_fd(req);

	g_get_current_time(&end);
	interval = __get_pending_interval(_request_get_start_time(req), &end);
	reply = __create_reply_info(interval, pid, result, cmd, clifd);

	if (reply == NULL) {
		_send_result_to_client(clifd, -1);
		return NULL;
	}

	return reply;
}

int _request_reply_add_extra(request_reply_h handle, const char *key,
		void *extra, void (*extra_free_cb)(void *data))
{
	struct reply_info *reply = handle;
	struct extra_info *info = malloc(sizeof(struct extra_info));

	if (!info) {
		_E("Out of memory");
		return -1;
	}

	info->extra = extra;
	info->free_cb = extra_free_cb;
	info->key = strdup(key);
	if (!info->key) {
		_E("Out of memory");
		free(info);
		return -1;
	}

	reply->extra_list = g_list_append(reply->extra_list, info);

	return 0;
}

int _request_reply_foreach_extra(int pid, int (*callback)(const char *key, void *data))
{
	struct pending_item *item;
	GList *iter;
	struct reply_info *info;
	struct extra_info *extra_info;
	GList *extra_iter;

	item = g_hash_table_lookup(pending_table, GINT_TO_POINTER(pid));
	if (!item)
		return -1;

	iter = item->reply_list;
	while (iter) {
		info = iter->data;
		extra_iter = info->extra_list;
		while (extra_iter) {
			extra_info = extra_iter->data;
			if (!callback(extra_info->key, extra_info->extra))
				extra_info->extra = NULL;
			extra_iter = g_list_next(extra_iter);
		}

		iter = g_list_next(iter);
	}

	return 0;
}

int _request_usr_init(uid_t uid)
{
	GList *iter;
	request_h req;
	int r;
	struct pending_item *item;

	_noti_send("request.user_init", uid, 0, NULL, NULL);
	item = g_hash_table_lookup(pending_table, GINT_TO_POINTER(getpid()));
	if (item == NULL || item->pending_list == NULL)
		return 0;

	iter = g_list_first(item->pending_list);
	while (iter) {
		req = (request_h)iter->data;
		iter = g_list_next(iter);
		if (req == NULL)
			continue;

		req->t_pid = 0;
		if (req->t_uid < REGULAR_UID_MIN)
			req->t_uid = uid;

		if (req->t_uid == uid) {
			g_source_remove(req->timer);
			req->timer = 0;
			item->pending_list = g_list_remove(item->pending_list,
					req);

			_request_set_request_type(req, NULL);
			r = __check_request(req);
			if (r == 0)
				g_idle_add(__dispatch_request, (gpointer)req);
			else if (r < 0)
				__free_request(req);
		}
	}

	return 0;
}

static void __cynara_response_callback(enum amd_cynara_res res, request_h req)
{
	int ret;

	if (res == AMD_CYNARA_ALLOWED) {
		ret = __check_target_user(req);
		if (ret > 0) {
			ret = __add_request_on_pending_list(req);
			if (ret < 0) {
				_E("Failed to add request on pending list");
				_request_send_result(req, -EAGAIN);
				__free_request(req);
			}

			return;
		}

		_request_set_request_type(req, NULL);
		ret = __check_request(req);
		if (ret < 0) {
			_request_send_result(req, ret);
			__free_request(req);
			return;
		} else if (ret > 0) {
			return;
		}
		__dispatch_request((gpointer)req);
	} else {
		_E("request has been denied by cynara");
		ret = -EILLEGALACCESS;
		_request_send_result(req, ret);
		__free_request(req);
	}

	return;
}

static bool __is_indirect_request(request_h req)
{
	const char *req_type;

	req_type = _request_get_request_type(req);
	if (!req_type)
		return false;

	if (!strcmp(req_type, "indirect-request"))
		return true;

	return false;
}

static int __add_request_on_pending_list(request_h req)
{
	struct pending_item *item;
	unsigned int interval;
	GTimeVal end;
	int len;

	item = g_hash_table_lookup(pending_table,
			GINT_TO_POINTER(getpid()));
	if (item == NULL) {
		item = calloc(1, sizeof(struct pending_item));
		if (item == NULL) {
			_E("Out of memory");
			return -1;
		}
		item->pid = getpid();
		g_hash_table_insert(pending_table,
				GINT_TO_POINTER(getpid()),
				item);
	}

	len = g_list_length(item->pending_list);
	if (len <= PENDING_MESSAGE_MAX_CNT) {
		/*
		 * To find the request from pending table, the target request
		 * is set to the process ID of amd.
		 */
		req->t_pid = getpid();

		if (req->uid >= REGULAR_UID_MIN || __is_indirect_request(req)) {
			g_get_current_time(&end);
			interval = __get_pending_interval(
					_request_get_start_time(req), &end);
			req->timer = g_timeout_add(interval,
					__timeout_request, req);
		} else {
			_request_send_result(req, 0);
			req->timer = g_timeout_add(SYSTEM_REQUEST_TIMEOUT,
					__timeout_request, req);
		}

		item->pending_list = g_list_append(item->pending_list,
				req);
		_W("request(%s[%d]:%d:%u) is added on pending list",
				aul_cmd_convert_to_string(req->cmd),
				req->cmd, req->pid, req->t_uid);
	} else {
		_W("user(%u) not logged", req->t_uid);
		return -1;
	}

	return 0;
}

static gboolean __request_handler(GIOChannel *io, GIOCondition cond,
		gpointer data)
{
	int fd = g_io_channel_unix_get_fd(io);
	app_pkt_t *pkt;
	int ret;
	int clifd;
	struct ucred cr;
	request_h req;

	pkt = aul_sock_recv_pkt(fd, &clifd, &cr);
	if (pkt == NULL) {
		_E("recv error");
		return G_SOURCE_CONTINUE;
	}

	req = __get_request(clifd, pkt, cr);
	if (req == NULL) {
		close(clifd);
		free(pkt);
		return G_SOURCE_CONTINUE;
	}
	free(pkt);

	if (req->uid >= REGULAR_UID_MIN || __is_indirect_request(req)) {
		if (req->uid >= REGULAR_UID_MIN && req->uid != req->t_uid) {
			_E("request has been deined - uid(%d), target_uid(%d)",
					req->uid, req->t_uid);
			ret = -EILLEGALACCESS;
			_request_send_result(req, ret);
			__free_request(req);
			return G_SOURCE_CONTINUE;
		}

		ret = _cynara_check_privilege(req, __cynara_response_callback);
		if (ret < 0) {
			_E("request has been denied by cynara");
			ret = -EILLEGALACCESS;
			_request_send_result(req, ret);
			__free_request(req);
			return G_SOURCE_CONTINUE;
		} else if (ret == AMD_CYNARA_UNKNOWN) {
			return G_SOURCE_CONTINUE;
		} else {
			ret = __check_target_user(req);
			if (ret > 0 && req->cmd != LAUNCHPAD_LAUNCH_SIGNAL) {
				ret = __add_request_on_pending_list(req);
				if (ret < 0) {
					_E("Failed to add request on pending list");
					_request_send_result(req, -EAGAIN);
					__free_request(req);
				}

				return G_SOURCE_CONTINUE;
			}
		}
	} else {
		ret = __check_target_user(req);
		if (ret != 0 && (req->cmd == APP_START_ASYNC ||
					req->cmd == APP_START_RES_ASYNC)) {
			ret = __add_request_on_pending_list(req);
			if (ret < 0) {
				_E("Failed to add request on pending list");
				_request_send_result(req, -EAGAIN);
				__free_request(req);
			}

			return G_SOURCE_CONTINUE;
		}
	}

	_request_set_request_type(req, NULL);
	ret = __check_request(req);
	if (ret < 0) {
		_request_send_result(req, ret);
		__free_request(req);
		return G_SOURCE_CONTINUE;
	} else if (ret > 0) {
		return G_SOURCE_CONTINUE;
	}

	__dispatch_request((gpointer)req);

	return G_SOURCE_CONTINUE;
}

int _request_get_fd(request_h req)
{
	return req->clifd;
}

int _request_get_pid(request_h req)
{
	return req->pid;
}

pid_t _request_get_target_pid(request_h req)
{
	return req->t_pid;
}

bundle *_request_get_bundle(request_h req)
{
	return req->kb;
}

int _request_get_len(request_h req)
{
	return req->len;
}

unsigned char *_request_get_raw(request_h req)
{
	return req->data;
}

GTimeVal *_request_get_start_time(request_h req)
{
	return &req->start;
}

int _request_set_request_type(request_h req, const char *req_type)
{
	if (!req || !req->kb)
		return -1;

	bundle_del(req->kb, AUL_K_REQUEST_TYPE);

	if (req_type)
		bundle_add(req->kb, AUL_K_REQUEST_TYPE, req_type);

	return 0;
}

const char *_request_get_request_type(request_h req)
{
	if (!req || !req->kb)
		return NULL;

	return bundle_get_val(req->kb, AUL_K_REQUEST_TYPE);
}

request_h _request_create_local(int cmd, uid_t uid, int pid, bundle *kb)
{
	request_h req;

	req = (request_h)malloc(sizeof(struct request_s));
	if (req == NULL) {
		_E("out of memory");
		return NULL;
	}

	g_get_current_time(&req->start);
	req->timer = 0;
	req->clifd = -1;
	req->pid = pid;
	req->t_pid = 0;
	req->uid = getuid();
	req->t_uid = uid;
	req->cmd = cmd;
	req->len = 0;
	req->opt = AUL_SOCK_NONE;
	req->kb = bundle_dup(kb);

	return req;
}

void _request_free_local(request_h req)
{
	if (req == NULL)
		return;

	if (req->kb)
		bundle_free(req->kb);

	free(req);
}

int _request_get_cmd(request_h req)
{
	return req->cmd;
}

int _request_set_cmd(request_h req, int cmd)
{
	req->cmd = cmd;

	return 0;
}

int _request_remove_fd(request_h req)
{
	int r = req->clifd;

	req->clifd = 0;

	return r;
}

uid_t _request_get_target_uid(request_h req)
{
	return req->t_uid;
}

uid_t _request_get_uid(request_h req)
{
	return req->uid;
}

int _request_send_raw(request_h req, int cmd, unsigned char *data, int len)
{
	return aul_sock_send_raw_with_fd(_request_remove_fd(req), cmd, data,
			len, AUL_SOCK_NOREPLY);
}

int _request_send_result(request_h req, int res)
{
	if (req->clifd && (req->opt & AUL_SOCK_NOREPLY))
		close(_request_remove_fd(req));
	else if (req->clifd)
		_send_result_to_client(_request_remove_fd(req), res);

	return 0;
}

int _request_register_cmds(const request_cmd_dispatch *cmds, int cnt)
{
	int i;

	if (cnt <= 0 || !__dispatch_table || !cmds)
		return -1;

	for (i = 0; i < cnt; i++) {
		g_hash_table_insert(__dispatch_table,
				GINT_TO_POINTER(cmds[i].cmd),
				(gpointer)(&cmds[i]));
	}

	return 0;
}

int _request_init(void)
{
	_D("request init");
	pending_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
			NULL, __free_pending_item);
	if (pending_table == NULL) {
		_E("Failed to create pending table");
		_request_fini();
		return -1;
	}

	amd_fd = _create_sock_activation();
	if (amd_fd == -1) {
		_D("Create server socket without socket activation");
		amd_fd = _create_server_sock();
		if (amd_fd == -1) {
			_E("Create server socket failed.");
			_request_fini();
			return -1;
		}
	}

	amd_io = g_io_channel_unix_new(amd_fd);
	if (amd_io == NULL) {
		_E("Failed to create gio channel");
		_request_fini();
		return -1;
	}

	amd_wid = g_io_add_watch(amd_io, G_IO_IN, __request_handler, NULL);
	if (amd_wid == 0) {
		_E("Failed to add gio watch");
		_request_fini();
		return -1;
	}

	__dispatch_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
			NULL, NULL);

	return 0;
}

void _request_fini(void)
{
	_D("request fini");
	if (amd_wid) {
		g_source_remove(amd_wid);
		amd_wid = 0;
	}

	if (amd_io) {
		g_io_channel_unref(amd_io);
		amd_io = NULL;
	}

	if (amd_fd > 0) {
		close(amd_fd);
		amd_fd = 0;
	}

	if (pending_table) {
		g_hash_table_destroy(pending_table);
		pending_table = NULL;
	}

	if (__dispatch_table) {
		g_hash_table_destroy(__dispatch_table);
		__dispatch_table = NULL;
	}
}
