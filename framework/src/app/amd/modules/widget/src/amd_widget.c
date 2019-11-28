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
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <aul.h>
#include <aul_cmd.h>
#include <aul_svc.h>
#include <aul_svc_priv_key.h>
#include <aul_sock.h>
#include <bundle.h>
#include <bundle_internal.h>

#include "amd.h"
#include "amd_widget_private.h"
#include "amd_widget_logger.h"

#ifndef AUL_K_WIDGET_OPERATION
#define AUL_K_WIDGET_OPERATION "__WIDGET_OP__"
#endif
#define MAX_NR_OF_DESCRIPTORS 2
#define MAX_PID_STR_BUFSZ 20
#define REGULAR_UID_MIN 5000
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

typedef struct _widget_t {
	char *pkg_id;
	char *widget_id;
	int pid;
	uid_t uid;
	GList *instances;
} widget_t;

struct restart_widget_info {
	char *appid;
	char *pkgid;
	GList *widget_list;
	bool is_faulted;
	int status;
	pid_t pid;
	uid_t uid;
	pid_t viewer_pid;
	int count;
	guint timer;
};

struct restart_info {
	char *appid;
	int count;
	guint timer;
};

struct widget_status_info {
	const char *endpoint;
	const char *widget_id;
	const char *instance_id;
	const char *pkg_id;
	const char *is_fault;
	int status;
	int pid;
	uid_t uid;
};

static GList *__widgets;
static GList *__update_widgets;
static GList *__oom_restart_widgets;
static GList *__restart_widgets;

static widget_t *__create_widget(const char *widget_id, const char *pkgid,
		pid_t pid, uid_t uid);
static void __free_widget(gpointer data);

static int __send_status_info(struct widget_status_info *info)
{
	char buf[MAX_PID_STR_BUFSZ];
	bundle *envelope;
	int r;

	envelope = bundle_create();
	if (envelope == NULL) {
		LOGE("Out of memory");
		return -1;
	}

	snprintf(buf, sizeof(buf), "%d", info->pid);
	bundle_add(envelope, AUL_K_COM_SENDER_PID, buf);
	bundle_add(envelope, AUL_K_WIDGET_ID, info->widget_id);
	bundle_add_byte(envelope, AUL_K_WIDGET_STATUS,
			&info->status, sizeof(int));

	if (info->instance_id) {
		bundle_add(envelope, AUL_K_WIDGET_INSTANCE_ID,
				info->instance_id);
	}
	if (info->pkg_id)
		bundle_add(envelope, AUL_K_PKGID, info->pkg_id);
	if (info->is_fault)
		bundle_add(envelope, AUL_K_IS_FAULT, info->is_fault);

	r = amd_app_com_send(info->endpoint, info->pid, envelope, info->uid);
	bundle_free(envelope);
	LOGW("endpoint(%s), widget(%s:%d), status(%d), is_faulted(%s)",
			info->endpoint, info->widget_id,
			info->pid, info->status,
			info->is_fault);
	_widget_logger_print("SEND_STATUS", "widget(%s), pid(%d) "
			"status(%d), is_faulted(%s)",
			info->widget_id, info->pid,
			info->status, info->is_fault);
	return r;
}

static void __free_widget(gpointer data)
{
	widget_t *widget = (widget_t *)data;

	if (widget->pkg_id)
		free(widget->pkg_id);
	if (widget->widget_id)
		free(widget->widget_id);
	if (widget->instances)
		g_list_free_full(widget->instances, free);
	free(widget);
}

static widget_t *__create_widget(const char *widget_id, const char *pkgid,
		pid_t pid, uid_t uid)
{
	widget_t *widget;

	widget = (widget_t *)calloc(1, sizeof(widget_t));
	if (widget == NULL) {
		LOGE("Out of memory");
		return NULL;
	}

	widget->widget_id = strdup(widget_id);
	if (widget->widget_id == NULL) {
		LOGE("Out of memory");
		free(widget);
		return NULL;
	}

	if (pkgid) {
		widget->pkg_id = strdup(pkgid);
		if (widget->pkg_id == NULL) {
			LOGE("Out of memory");
			free(widget->widget_id);
			free(widget);
			return NULL;
		}
	}

	widget->pid = pid;
	widget->uid = uid;

	return widget;
}

static widget_t *__find_widget(const char *widget_id, int pid, uid_t uid)
{
	GList *widget_list = __widgets;
	widget_t *widget;

	while (widget_list) {
		widget = (widget_t *)widget_list->data;
		if (strcmp(widget->widget_id, widget_id) == 0) {
			if (widget->pid == pid && widget->uid == uid)
				return widget;
		}

		widget_list = widget_list->next;
	}

	return NULL;
}

static widget_t *__find_instance(const char *widget_id, const char *instance_id)
{
	GList *widget_list = __widgets;
	GList *instance_list;
	widget_t *widget;

	while (widget_list) {
		widget = (widget_t *)widget_list->data;
		if (strcmp(widget->widget_id, widget_id) == 0
						&& widget->instances) {
			instance_list = g_list_find_custom(widget->instances,
					instance_id, (GCompareFunc)g_strcmp0);

			if (instance_list)
				return widget;
		}

		widget_list = widget_list->next;
	}

	return NULL;
}

static bool __widget_exist(int pid, uid_t uid)
{
	GList *widget_list = __widgets;
	widget_t *widget;

	while (widget_list) {
		widget = (widget_t *)widget_list->data;
		if (widget->pid == pid && widget->uid == uid)
			return true;

		widget_list = widget_list->next;
	}
	return false;
}

static int __widget_pre_add(bundle *kb, int pid, uid_t uid)
{
	widget_t *widget;
	const char *widget_id;
	const char *instance_id;
	const char *operation;

	if (!kb) {
		LOGE("Invalid parameter");
		return -1;
	}

	operation = bundle_get_val(kb, AUL_K_WIDGET_OPERATION);
	if (!operation || strcmp(operation, "create") != 0)
		return -1;

	widget_id = bundle_get_val(kb, AUL_K_WIDGET_ID);
	if (!widget_id)
		return -1;

	instance_id = bundle_get_val(kb, AUL_K_WIDGET_INSTANCE_ID);
	if (!instance_id)
		return -1;

	widget = __find_instance(widget_id, instance_id);
	if (!widget) {
		widget = __find_widget(widget_id, pid, uid);
		if (!widget) {
			widget = __create_widget(widget_id, NULL, pid, uid);
			if (!widget)
				return -1;

			__widgets = g_list_append(__widgets, widget);
		}
	} else {
		if (widget->pid != pid) {
			LOGW("Process ID(%d) of %s is changed to %d",
					widget->pid, widget_id, pid);
			widget->pid = pid;
		}
	}

	_widget_logger_print("PRE_ADD", "instance(%s), pid(%d)",
			instance_id, pid);

	return 0;
}

static int __widget_add(const char *widget_id, const char *instance_id,
		int pid, uid_t uid)
{
	widget_t *widget;
	char *id;

	if (!widget_id || !instance_id)
		return -1;

	id = strdup(instance_id);
	if (!id) {
		LOGE("out of memory");
		return -1;
	}

	widget = __find_instance(widget_id, instance_id);
	if (!widget) {
		widget = __find_widget(widget_id, pid, uid);
		if (!widget) {
			widget = __create_widget(widget_id, NULL, pid, uid);
			if (!widget) {
				LOGE("out of memory");
				free(id);
				return -1;
			}

			__widgets = g_list_append(__widgets, widget);
		}
		widget->pid = pid;
		widget->instances = g_list_append(widget->instances, id);
	} else {
		LOGW("instance recovery: %s - %s(%d)",
				widget_id, instance_id, pid);
		if (widget->pid != pid) {
			LOGW("Process ID(%d) of %s is changed to %d",
					widget->pid, widget_id, pid);
			widget->pid = pid;
		}
		free(id);
	}

	LOGD("widget instance added: %s - %s (%d:%d)", widget_id, instance_id,
								uid, pid);
	return 0;
}

static int __widget_del(const char *widget_id, const char *instance_id)
{
	widget_t *widget;
	GList *stored_list;

	if (!widget_id || !instance_id)
		return -1;

	widget = __find_instance(widget_id, instance_id);
	if (!widget) {
		LOGE("Failed to find instance(%s) of widget(%s)",
				instance_id, widget_id);
		return -1;
	}
	stored_list = g_list_find_custom(widget->instances, instance_id,
			 (GCompareFunc)g_strcmp0);

	if (stored_list) {
		LOGW("widget instace deleted: %s - %s (%d:%d)",
				widget->widget_id,
				instance_id,
				widget->uid,
				widget->pid);
		widget->instances = g_list_remove_link(widget->instances,
				stored_list);
		if (!widget->instances) {
			__widgets = g_list_remove(__widgets, widget);
			__free_widget(widget);
		}

		free(stored_list->data);
		g_list_free(stored_list);
		return 0;
	}

	return -1;
}

static int __widget_list(const char *widget_id, amd_request_h req)
{
	bundle *rvalue;
	widget_t *widget;
	GList *widget_list = __widgets;
	GList *instance_list;
	char pid_buf[10];
	int fd;

	if (!widget_id)
		return -1;

	rvalue = bundle_create();
	if (!rvalue) {
		LOGE("out of memory");
		return -1;
	}

	LOGD("start instance list");

	while (widget_list) {
		widget = (widget_t *)widget_list->data;
		if (strcmp(widget->widget_id, widget_id) == 0) {
			instance_list = widget->instances;
			snprintf(pid_buf, sizeof(pid_buf), "%d", widget->pid);
			while (instance_list) {
				LOGD("%s - %s", widget_id,
					(const char *)instance_list->data);
				bundle_add_str(rvalue, instance_list->data,
								pid_buf);
				instance_list = instance_list->next;
			}
		}
		widget_list = widget_list->next;
	}

	LOGD("end instance list");

	fd = amd_request_remove_fd(req);
	aul_sock_send_bundle_with_fd(fd, 0, rvalue, AUL_SOCK_NOREPLY);
	bundle_free(rvalue);

	return 0;
}

static int __widget_update(const char *widget_id, amd_request_h req)
{
	char *instance_id = NULL;
	char *appid = NULL;
	bundle *kb = amd_request_get_bundle(req);
	int ret = -1;
	widget_t *widget;
	GList *widget_list = __widgets;
	bool dummy;
	bool dummy_mode;

	if (!kb || !widget_id) {
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	bundle_get_str(kb, AUL_K_APPID, &appid);
	if (!appid) {
		LOGE("missing appid:%s", widget_id);
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	bundle_get_str(kb, AUL_K_WIDGET_INSTANCE_ID, &instance_id);
	if (!instance_id) { /* all instances */
		while (widget_list) {
			widget = (widget_t *)widget_list->data;
			if (strcmp(widget->widget_id, widget_id) == 0
				&& widget->pid > 0) {
				bundle_del(kb, AUL_K_TARGET_PID);
				bundle_add_byte(kb, AUL_K_TARGET_PID,
						(void *)&widget->pid,
						sizeof(widget->pid));

				ret = amd_launch_start_app(appid, req, &dummy,
						&dummy_mode, false);
				LOGD("update widget: %s(%d)", widget->widget_id,
								widget->pid);
			}
			widget_list = widget_list->next;
		}
	} else {
		widget = __find_instance(widget_id, instance_id);
		if (widget) {
			if (widget->pid == -1) {
				LOGW("widget process is not running: %s",
					widget->widget_id);
				return ret;
			}
			bundle_del(kb, AUL_K_TARGET_PID);
			bundle_add_byte(kb, AUL_K_TARGET_PID,
				(void *)&widget->pid, sizeof(widget->pid));
		}
		ret = amd_launch_start_app(appid, req, &dummy, &dummy_mode, false);
		LOGD("update widget: %s", widget_id);
	}

	return ret;
}

static int __widget_cleanup(int pid, uid_t uid, int viewer_pid)
{
	GList *widget_list = __widgets;
	widget_t *widget;
	amd_app_status_h viewer_status;

	LOGD("viewer pid %d", viewer_pid);
	while (widget_list) {
		widget = (widget_t *)widget_list->data;
		widget_list = widget_list->next;
		if (widget->pid == pid && widget->uid == uid) {
			viewer_status = amd_app_status_find_by_pid(viewer_pid);
			if (viewer_status == NULL) {
				__widgets = g_list_remove(__widgets, widget);
				__free_widget(widget);
				LOGW("remove widget(%d) from list", pid);
			} else {
				LOGW("viewer pid(%d), widget pid(%d)",
						viewer_pid, pid);
				widget->pid = -1;
			}
		}
	}

	LOGD("cleanup widget %d:%d", pid, uid);

	return 0;
}

static int __widget_get_pid(const char *widget_id, const char *instance_id)
{
	widget_t *widget;

	widget = __find_instance(widget_id, instance_id);
	if (!widget)
		return -1;

	return widget->pid;
}

static int __widget_count(const char *widget_id, uid_t uid)
{
	widget_t *widget;
	GList *widget_list = __widgets;
	GList *instance_list;
	int count = 0;

	if (!widget_id)
		return -1;

	while (widget_list) {
		widget = (widget_t *)widget_list->data;
		if (strcmp(widget->widget_id, widget_id) == 0 &&
				widget->uid == uid) {
			instance_list = widget->instances;
			if (instance_list)
				count += g_list_length(instance_list);
		}
		widget_list = widget_list->next;
	}
	LOGW("widget(%s) count: %d", widget_id, count);

	return count;
}

static int __widget_verify_cmd(amd_request_h req)
{
	bundle *kb = amd_request_get_bundle(req);
	const char *command;
	const char *instance_id;
	const char *widget_id;
	widget_t *widget;

	if (!kb) {
		LOGE("invalid argument");
		return -1;
	}

	widget_id = bundle_get_val(kb, AUL_K_WIDGET_ID);
	if (!widget_id)
		return 0;

	instance_id = bundle_get_val(kb, AUL_K_WIDGET_INSTANCE_ID);
	if (!instance_id)
		return 0;

	command = bundle_get_val(kb, AUL_K_WIDGET_OPERATION);
	if (!command)
		return 0;

	if (strcmp(command, "create") == 0)
		return 0;

	widget = __find_instance(widget_id, instance_id);
	if (!widget) {
		LOGE("invalid command: %s - target instance %s is not exist",
			command, instance_id);
		return -EREJECTED;
	}

	return 0;
}

static int __validate_widget_owner(amd_request_h req)
{
	amd_app_status_h status;
	const char *appid;
	char *widget_id = NULL;
	const char *appid_part = NULL;
	bundle *kb = amd_request_get_bundle(req);

	status = amd_app_status_find_by_pid(amd_request_get_pid(req));
	if (!status)
		return -1;

	appid = amd_app_status_get_appid(status);
	bundle_get_str(kb, AUL_K_WIDGET_ID, &widget_id);
	if (!widget_id || !appid)
		return -1;

	appid_part = g_strstr_len(widget_id, strlen(widget_id), "@");
	if (appid_part)
		appid_part = appid_part + 1;
	else
		appid_part = widget_id;

	return strcmp(appid_part, appid);
}

static int __dispatch_widget_change_status(amd_request_h req)
{
	bundle *kb = amd_request_get_bundle(req);
	amd_app_status_h caller_status;
	const char *caller_pkgid;
	const char *caller_appid = NULL;
	const char *status;
	int pid;

	if (__validate_widget_owner(req) < 0) {
		LOGE("Invalid sender");
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	status = bundle_get_val(kb, AUL_K_STATUS);
	if (status == NULL) {
		LOGE("Failed to get status");
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	pid = amd_request_get_pid(req);
	caller_status = amd_app_status_find_by_pid(pid);
	if (!caller_status)
		return 0; /* not app? */

	caller_pkgid = amd_app_status_get_pkgid(caller_status);
	if (!caller_pkgid) {
		LOGE("can not get caller pkgid");
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	caller_appid = amd_app_status_get_appid(caller_status);
	if (!caller_appid) {
		LOGE("can not get caller appid");
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	LOGI("send status %d, %s, %s, %s", pid, caller_appid,
			caller_pkgid, status);

	aul_send_app_status_change_signal(pid,
			caller_appid,
			caller_pkgid,
			status,
			APP_TYPE_WIDGET);
	_widget_logger_print("CHANGE_STATUS", "widget_id(%s), status(%s)",
			caller_appid, status);
	return amd_request_send_result(req, 0);
}

static int __dispatch_widget_add_del(amd_request_h req)
{
	bundle *kb = amd_request_get_bundle(req);
	char *widget_id = NULL;
	char *instance_id = NULL;
	int ret;
	int cmd = amd_request_get_cmd(req);
	const char *tag;

	if (cmd == WIDGET_ADD && __validate_widget_owner(req) != 0) {
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	bundle_get_str(kb, AUL_K_WIDGET_ID, &widget_id);
	if (!widget_id) {
		LOGE("Failed to get widget id");
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	bundle_get_str(kb, AUL_K_WIDGET_INSTANCE_ID, &instance_id);
	if (!instance_id) {
		LOGE("Failed to get instance id");
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	if (amd_request_get_cmd(req) == WIDGET_ADD) {
		ret = __widget_add(widget_id, instance_id,
				amd_request_get_pid(req),
				amd_request_get_uid(req));
		tag = "ADD";
	} else {
		ret = __widget_del(widget_id, instance_id);
		tag = "DEL";
	}

	amd_request_send_result(req, ret);
	LOGW("[%s:%d] Instance ID(%s), Result(%d)",
			aul_cmd_convert_to_string(cmd),
			cmd, instance_id, ret);
	_widget_logger_print(tag, "instance(%s), result(%d)",
			instance_id, ret);
	return ret;
}

static int __validate_widget_caller(amd_request_h req)
{
	bundle *kb = amd_request_get_bundle(req);
	char *appid = NULL;
	amd_appinfo_h target;
	const char *target_pkgid;
	amd_app_status_h caller_status;
	const char *caller_pkgid;
	pid_t caller_pid = amd_request_get_pid(req);
	char attr[512] = { 0, };
	int r;

	if (amd_request_get_uid(req) < REGULAR_UID_MIN) {
		LOGD("bypass caller package check");
		return 0;
	}

	bundle_get_str(kb, AUL_K_APPID, &appid);
	if (!appid) {
		LOGE("no appid provided");
		return -1;
	}

	target = amd_appinfo_find(amd_request_get_uid(req), appid);
	if (!target) {
		LOGE("can not find appinfo of %s", appid);
		return -1;
	}

	target_pkgid = amd_appinfo_get_value(target, AMD_AIT_PKGID);
	if (!target_pkgid) {
		LOGE("can not get pkgid %s", target_pkgid);
		return -1;
	}

	caller_status = amd_app_status_find_by_effective_pid(caller_pid);
	if (!caller_status) {
		r = amd_proc_get_attr(caller_pid, attr, sizeof(attr));
		if (r != 0) {
			LOGE("Failed to get attr. caller(%d)", caller_pid);
			return -1;
		}

		if (!strcmp(attr, "User"))
			return 0;

		LOGE("Reject request. caller(%d)", caller_pid);
		return -1;
	}

	caller_pkgid = amd_app_status_get_pkgid(caller_status);
	if (!caller_pkgid) {
		LOGE("can not get caller pkgid");
		return -1;
	}

	LOGD("compare pkgid %s:%s", caller_pkgid, target_pkgid);
	if (strcmp(caller_pkgid, target_pkgid) == 0)
		return 0;

	return -1;
}

static int __send_message(int sock, const struct iovec *vec, int vec_size,
		const int *desc, int nr_desc)
{
	struct msghdr msg = {0,};
	int sndret;
	int desclen = 0;
	struct cmsghdr *cmsg = NULL;
	char buff[CMSG_SPACE(sizeof(int) * MAX_NR_OF_DESCRIPTORS)] = {0,};

	if (vec == NULL || vec_size < 1)
		return -EINVAL;
	if (nr_desc < 0 || nr_desc > MAX_NR_OF_DESCRIPTORS)
		return -EINVAL;
	if (desc == NULL)
		nr_desc = 0;

	msg.msg_iov = (struct iovec *)vec;
	msg.msg_iovlen = vec_size;

	/* sending ancillary data */
	if (nr_desc > 0) {
		msg.msg_control = buff;
		msg.msg_controllen = sizeof(buff);
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL)
			return -EINVAL;

		/* packing files descriptors */
		if (nr_desc > 0) {
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			desclen = cmsg->cmsg_len =
				CMSG_LEN(sizeof(int) * nr_desc);
			memcpy((int *)CMSG_DATA(cmsg), desc,
					sizeof(int) * nr_desc);
			cmsg = CMSG_NXTHDR(&msg, cmsg);
			LOGD("packing file descriptors done");
		}

		/* finished packing updating the corect length */
		msg.msg_controllen = desclen;
	} else {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}

	sndret = sendmsg(sock, &msg, 0);
	LOGD("sendmsg ret : %d", sndret);
	if (sndret < 0)
		return -errno;

	return sndret;
}

static int __dispatch_widget_get_content(amd_request_h req)
{
	int handles[2] = {0,};
	char iobuf[1];
	struct iovec vec = {
		.iov_base = iobuf,
		.iov_len = sizeof(iobuf)
	};
	int msglen = 0;
	int ret;
	bundle *kb = amd_request_get_bundle(req);
	struct timeval tv;
	int pid;
	char *widget_id = NULL;
	char *instance_id = NULL;

	if (__validate_widget_caller(req) != 0) {
		amd_request_send_result(req, -EILLEGALACCESS);
		return -1;
	}

	bundle_get_str(kb, AUL_K_WIDGET_ID, &widget_id);
	bundle_get_str(kb, AUL_K_WIDGET_INSTANCE_ID, &instance_id);

	pid = __widget_get_pid(widget_id, instance_id);
	if (pid < 0) {
		LOGE("can not find widget");
		amd_request_send_result(req, -ENOENT);
		return -1;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, handles) != 0) {
		LOGE("error create socket pair");
		amd_request_send_result(req, -1);
		return -1;
	}

	if (handles[0] == -1) {
		LOGE("error socket open");
		amd_request_send_result(req, -1);
		return -1;
	}

	tv.tv_sec = 5;
	tv.tv_usec = 0;

	ret = setsockopt(handles[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (ret < 0) {
		LOGE("cannot set SO_RCVTIMEO for socket %d", handles[0]);
		amd_request_send_result(req, -1);
		goto out;
	}

	ret = aul_sock_send_bundle(pid, amd_request_get_target_uid(req),
			amd_request_get_cmd(req), amd_request_get_bundle(req),
			AUL_SOCK_ASYNC);
	if (ret < 0) {
		LOGE("error while sending bundle");
		amd_request_send_result(req, -1);
		goto out;
	}

	msglen = __send_message(ret, &vec, 1, &(handles[0]), 1);
	if (msglen < 0) {
		LOGE("Error[%d]: while sending message to widget", -msglen);
		amd_request_send_result(req, -1);
		ret = -1;
		goto out;
	}

	msglen = __send_message(amd_request_get_fd(req), &vec, 1,
			&(handles[1]), 1);
	if (msglen < 0) {
		LOGE("Error[%d]: while sending message to caller", -msglen);
		amd_request_send_result(req, -1);
		ret = -1;
	}

out:
	close(handles[0]);
	close(handles[1]);

	return ret;
}

static int __dispatch_widget_list(amd_request_h req)
{
	bundle *kb = amd_request_get_bundle(req);
	char *widget_id = NULL;
	int ret;

	if (__validate_widget_caller(req) < 0) {
		amd_request_send_result(req, -EILLEGALACCESS);
		return -1;
	}

	bundle_get_str(kb, AUL_K_WIDGET_ID, &widget_id);
	if (!widget_id) {
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	ret = __widget_list(widget_id, req);

	return ret;
}

static int __dispatch_widget_update(amd_request_h req)
{
	bundle *kb = amd_request_get_bundle(req);
	char *widget_id = NULL;
	int ret;

	if (__validate_widget_caller(req) < 0) {
		amd_request_send_result(req, -EILLEGALACCESS);
		return -1;
	}

	bundle_get_str(kb, AUL_K_WIDGET_ID, &widget_id);
	if (!widget_id) {
		amd_request_send_result(req, -EINVAL);
		return -1;
	}

	/* update will pass bundle by app_control */
	amd_request_set_cmd(req, APP_START_ASYNC);

	ret = __widget_update(widget_id, req);
	if (ret < 0)
		return -1;

	_widget_logger_print("UPDATE", "widget_id(%s), result(%d)",
			widget_id, ret);

	return 0;
}

static int __dispatch_widget_count(amd_request_h req)
{
	bundle *kb = amd_request_get_bundle(req);
	char *widget_id = NULL;
	int count;

	bundle_get_str(kb, AUL_K_WIDGET_ID, &widget_id);
	if (!widget_id) {
		LOGE("Failed to get widget id. caller(%d)",
				amd_request_get_pid(req));
		amd_request_send_result(req, -EINVAL);
		return -1;
	}
	count = __widget_count(widget_id, amd_request_get_uid(req));
	LOGD("dispatch widget count %d", count);
	amd_request_send_result(req, count);

	_widget_logger_print("COUNT", "widget_id(%s), count(%d)",
			widget_id, count);

	return 0;
}

static bundle *__create_bundle(widget_t *widget)
{
	char buf[MAX_PID_STR_BUFSZ];
	amd_app_status_h app_status;
	bundle *b;

	app_status = amd_app_status_find_by_pid(widget->pid);
	if (app_status == NULL)
		return NULL;

	b = bundle_create();
	if (b == NULL) {
		LOGE("Out of memory");
		return NULL;
	}

	snprintf(buf, sizeof(buf), "%d", widget->pid);
	bundle_add_str(b, AUL_K_PID, buf);
	bundle_add_str(b, AUL_K_APPID, amd_app_status_get_appid(app_status));
	bundle_add_str(b, AUL_K_PKGID, amd_app_status_get_pkgid(app_status));
	bundle_add_str(b, AUL_K_EXEC, amd_app_status_get_app_path(app_status));
	bundle_add_str(b, AUL_K_WIDGET_ID, widget->widget_id);

	return b;
}

static int __send_running_info(widget_t *widget, int fd)
{
	char buf[MAX_PID_STR_BUFSZ];
	const char *instance_id;
	unsigned int surf;
	bundle_raw *b_raw = NULL;
	int len = 0;
	GList *iter;
	bundle *b;
	int r;

	b = __create_bundle(widget);
	if (b == NULL) {
		LOGE("Failed to create bundle");
		aul_sock_send_raw_with_fd(fd, APP_GET_INFO_ERROR,
				NULL, 0, AUL_SOCK_NOREPLY);
		return -1;
	}

	iter = widget->instances;
	while (iter) {
		instance_id = (const char *)iter->data;
		surf = 0;
		amd_noti_send("widget.running_info.send",
				GPOINTER_TO_INT(&surf), (int)widget->uid,
				(void *)instance_id, NULL);
		snprintf(buf, sizeof(buf), "%u", surf);
		bundle_del(b, AUL_K_WID);
		bundle_add_str(b, AUL_K_WID, buf);
		bundle_del(b, AUL_K_WIDGET_INSTANCE_ID);
		bundle_add_str(b, AUL_K_WIDGET_INSTANCE_ID, instance_id);

		bundle_encode(b, &b_raw, &len);
		if (b_raw == NULL) {
			LOGE("Failed to encode bundle");
			aul_sock_send_raw_with_fd(fd, APP_GET_INFO_ERROR,
					NULL, 0, AUL_SOCK_NOREPLY);
			bundle_free(b);
			return -1;
		}

		r = aul_sock_send_raw_with_fd(fd, APP_GET_INFO_OK,
				(unsigned char *)b_raw, len,
				AUL_SOCK_ASYNC | AUL_SOCK_BUNDLE);
		if (r < 0) {
			LOGE("Failed to send raw data: %d", r);
			free(b_raw);
			bundle_free(b);
			return -1;
		}
		free(b_raw);
		b_raw = NULL;

		iter = g_list_next(iter);
	}
	free(b_raw);
	bundle_free(b);

	return 0;
}

static int __dispatch_widget_running_info(amd_request_h req)
{
	uid_t target_uid = amd_request_get_target_uid(req);
	int fd = amd_request_remove_fd(req);
	widget_t *widget;
	GList *iter;
	int count = 0;
	int r;

	iter = __widgets;
	while (iter) {
		widget = (widget_t *)iter->data;
		if (widget && widget->uid == target_uid)
			count += g_list_length(widget->instances);

		iter = g_list_next(iter);
	}

	if (count == 0) {
		LOGE("Widget doesn't exist");
		amd_socket_send_result(fd, -1, true);
		return -1;
	}
	amd_socket_send_result(fd, count, false);

	iter = __widgets;
	while (iter) {
		widget = (widget_t *)iter->data;
		if (widget && widget->uid == target_uid) {
			r = __send_running_info(widget, fd);
			if (r < 0)
				break;
		}
		iter = g_list_next(iter);
	}
	close(fd);

	return 0;
}

static int __app_term_by_pid_async_checker(amd_cynara_caller_info_h info,
		amd_request_h req, void *data)
{
	int pid;
	char *term_pid;
	bundle *kb;
	amd_app_status_h status;
	amd_appinfo_h ai;
	const char *comp_type;

	kb = amd_request_get_bundle(req);
	if (kb == NULL) {
		LOGE("Failed to get bundle");
		return -1;
	}

	bundle_get_str(kb, AUL_K_APPID, &term_pid);
	if (term_pid == NULL) {
		LOGE("Failed to get process id");
		return -1;
	}

	pid = atoi(term_pid);
	status = amd_app_status_find_by_pid(pid);
	if (!status) {
		LOGE("Failed to find app status. pid(%d)", pid);
		return -1;
	}

	ai = amd_appinfo_find(amd_request_get_target_uid(req),
			amd_app_status_get_appid(status));
	if (!ai) {
		LOGE("Failed to find appinfo");
		return -1;
	}

	comp_type = amd_appinfo_get_value(ai, AMD_AIT_COMPTYPE);
	if (!comp_type)
		return -1;

	if (strcmp(comp_type, APP_TYPE_WIDGET) == 0) {
		return amd_cynara_simple_checker(info, req,
				PRIVILEGE_WIDGET_VIEWER);
	}

	return amd_cynara_simple_checker(info, req, data);
}

static amd_request_cmd_dispatch __dispatch_table[] = {
	{
		.cmd = WIDGET_ADD,
		.callback = __dispatch_widget_add_del
	},
	{
		.cmd = WIDGET_DEL,
		.callback = __dispatch_widget_add_del
	},
	{
		.cmd = WIDGET_LIST,
		.callback = __dispatch_widget_list
	},
	{
		.cmd = WIDGET_UPDATE,
		.callback = __dispatch_widget_update
	},
	{
		.cmd = WIDGET_COUNT,
		.callback = __dispatch_widget_count
	},
	{
		.cmd = WIDGET_GET_CONTENT,
		.callback = __dispatch_widget_get_content
	},
	{
		.cmd = WIDGET_RUNNING_INFO,
		.callback = __dispatch_widget_running_info
	},
	{
		.cmd = WIDGET_CHANGE_STATUS,
		.callback = __dispatch_widget_change_status
	},
};

static amd_cynara_checker __cynara_checkers[] = {
	{
		.cmd = APP_TERM_BY_PID_ASYNC,
		.checker = __app_term_by_pid_async_checker,
		.data = PRIVILEGE_APPMANAGER_KILL,
		.priority = 10
	},
	{
		.cmd = WIDGET_RUNNING_INFO,
		.checker = amd_cynara_simple_checker,
		.data = PRIVILEGE_PLATFORM,
		.priority = 10
	},
};

static void __destroy_restart_widget_info(gpointer data)
{
	struct restart_widget_info *info = (struct restart_widget_info *)data;

	if (info == NULL)
		return;

	if (info->timer > 0)
		g_source_remove(info->timer);
	if (info->widget_list)
		g_list_free_full(info->widget_list, free);
	if (info->pkgid)
		free(info->pkgid);
	if (info->appid)
		free(info->appid);
	free(info);
}

static struct restart_widget_info *__create_restart_widget_info(
		amd_app_status_h app_status)
{
	struct restart_widget_info *info;
	const char *appid = amd_app_status_get_appid(app_status);
	const char *pkgid = amd_app_status_get_pkgid(app_status);
	widget_t *widget;
	char *widget_id;
	GList *iter;

	info = calloc(1, sizeof(struct restart_widget_info));
	if (info == NULL) {
		LOGE("Out of memory");
		return NULL;
	}

	info->appid = strdup(appid);
	if (info->appid == NULL) {
		LOGE("Out of memory");
		free(info);
		return NULL;
	}

	info->pkgid = strdup(pkgid);
	if (info->pkgid == NULL) {
		LOGE("Out of memory");
		free(info->appid);
		free(info);
		return NULL;
	}

	iter = __widgets;
	while (iter) {
		widget = (widget_t *)iter->data;
		iter = g_list_next(iter);

		widget_id = strdup(widget->widget_id);
		if (widget_id == NULL) {
			LOGE("Out of memory");
			__destroy_restart_widget_info(info);
			return NULL;
		}

		info->widget_list = g_list_append(info->widget_list, widget_id);
	}

	info->is_faulted = !amd_app_status_is_exiting(app_status);
	info->pid = amd_app_status_get_pid(app_status);
	info->uid = amd_app_status_get_uid(app_status);
	info->viewer_pid = amd_app_status_get_first_caller_pid(app_status);
	info->count = 1;

	return info;
}

static struct restart_widget_info *__find_restart_widget_info(const char *appid,
		uid_t uid)
{
	struct restart_widget_info *info;
	GList *iter;

	iter = __restart_widgets;
	while (iter) {
		info = (struct restart_widget_info *)iter->data;
		if (!strcmp(info->appid, appid) && info->uid == uid)
			return info;

		iter = g_list_next(iter);
	}

	return NULL;
}

static gboolean __restart_timeout_handler(void *data)
{
	struct restart_widget_info *info = (struct restart_widget_info *)data;

	LOGW("appid (%s)", info->appid);
	__restart_widgets = g_list_remove(__restart_widgets, info);
	/* timer source will be removed after returing this callback */
	info->timer = 0;
	__destroy_restart_widget_info(info);

	return G_SOURCE_REMOVE;
}

static bool __check_restart(amd_app_status_h app_status)
{
	struct restart_widget_info *info;
	const char *appid = amd_app_status_get_appid(app_status);;
	uid_t uid = amd_app_status_get_uid(app_status);

	info = __find_restart_widget_info(appid, uid);
	if (info == NULL) {
		info = __create_restart_widget_info(app_status);
		if (info == NULL)
			return false;

		__restart_widgets = g_list_append(__restart_widgets, info);
		info->timer = g_timeout_add(10 * 1000,
				__restart_timeout_handler, info);
	} else {
		info->count++;
		if (info->count > 5) {
			LOGW("Failed to recover the widget(%s:%u)",
					info->appid, info->uid);
			__restart_widgets = g_list_remove(__restart_widgets,
					info);
			__destroy_restart_widget_info(info);
			return false;
		}

		if (info->timer > 0) {
			g_source_remove(info->timer);
			info->timer = g_timeout_add(10 * 1000,
					__restart_timeout_handler, info);
		}
	}

	LOGD("appid(%s), uid(%u), count(%d)", appid, uid, info->count);

	return true;
}

static void __widget_send_dead_signal(pid_t pid, uid_t uid, const char *pkgid,
		bool is_faulted)
{
	widget_t *widget;
	GList *iter;
	struct widget_status_info info = {
		.endpoint = "widget.status",
		.widget_id = NULL,
		.instance_id = NULL,
		.pkg_id = pkgid,
		.is_fault = is_faulted ? "true" : "false",
		.status = AUL_WIDGET_LIFE_CYCLE_EVENT_APP_DEAD,
		.pid = pid,
		.uid = uid
	};

	iter = __widgets;
	while (iter) {
		widget = (widget_t *)iter->data;
		if (widget->pid == pid && widget->uid == uid) {
			info.widget_id = widget->widget_id;
			__send_status_info(&info);
		}
		iter = g_list_next(iter);
	}
}

static void __widget_send_restart_signal(pid_t pid, uid_t uid, pid_t viewer_pid,
		const char *pkgid, bool is_faulted)
{
	widget_t *widget;
	GList *iter;
	amd_app_status_h app_status;
	struct widget_status_info info;

	app_status = amd_app_status_find_by_pid(viewer_pid);
	if (app_status == NULL)
		return;

	info.endpoint = amd_app_status_get_appid(app_status);
	info.widget_id = NULL;
	info.instance_id = NULL;
	info.pkg_id = pkgid;
	info.is_fault = is_faulted ? "true" : "false";
	info.status = AUL_WIDGET_INSTANCE_EVENT_APP_RESTART_REQUEST;
	info.pid = pid;
	info.uid = uid;

	iter = __widgets;
	while (iter) {
		widget = (widget_t *)iter->data;
		if (widget->pid == pid && widget->uid == uid) {
			info.widget_id = widget->widget_id;
			__send_status_info(&info);
		}
		iter = g_list_next(iter);
	}
}

static widget_t *__find_pending_restart_widget(const char *widget_id, pid_t pid,
		uid_t uid, GList *pending_list)
{
	widget_t *widget;
	GList *iter;

	iter = pending_list;
	while (iter) {
		widget = (widget_t *)iter->data;
		if (!strcmp(widget->widget_id, widget_id) &&
				widget->uid == uid &&
				widget->pid == pid)
			return widget;

		iter = g_list_next(iter);
	}

	return NULL;
}

static int __add_pending_restart_info(pid_t pid, uid_t uid,
		const char *pkgid, GList **pending_list)
{
	widget_t *widget;
	widget_t *pending_info;
	GList *iter;

	iter = __widgets;
	while (iter) {
		widget = (widget_t *)iter->data;
		iter = g_list_next(iter);

		pending_info = __find_pending_restart_widget(widget->widget_id,
				pid, widget->uid, *pending_list);
		if (pending_info == NULL && widget->pid == pid) {
			pending_info = __create_widget(widget->widget_id,
					pkgid, widget->pid, widget->uid);
			if (pending_info == NULL)
				return -1;
			*pending_list = g_list_append(*pending_list,
					pending_info);
			LOGW("adding pending restart info: %s, %d, %d",
					widget->widget_id, widget->pid,
					widget->uid);
		}
	}

	return 0;
}

static void __flush_pending_restart_list(const char *pkgid, uid_t uid,
		GList **pending_list)
{
	widget_t *widget;
	GList *iter;
	struct widget_status_info info = {
		.endpoint = "widget.status",
		.widget_id = NULL,
		.instance_id = NULL,
		.pkg_id = NULL,
		.is_fault = "true",
		.status = AUL_WIDGET_LIFE_CYCLE_EVENT_APP_DEAD,
		.pid = -1,
		.uid = 0
	};

	if (pending_list == NULL || *pending_list == NULL)
		return;

	iter = *pending_list;
	while (iter) {
		widget = (widget_t *)iter->data;
		iter = g_list_next(iter);
		if ((uid < REGULAR_UID_MIN || uid == widget->uid) &&
				(pkgid == NULL ||
				 !strcmp(widget->pkg_id, pkgid))) {
			*pending_list = g_list_remove(*pending_list, widget);
			info.widget_id = widget->widget_id;
			info.pkg_id = widget->pkg_id;
			info.pid = widget->pid;
			info.uid = widget->uid;
			LOGW("sending pending restart status: %s, %d, %d",
					info.widget_id, info.pid, info.uid);
			__send_status_info(&info);
			__free_widget(widget);
		}
	}
}

static void __widget_flush_oom_restart_list(void)
{
	__flush_pending_restart_list(NULL, 0, &__oom_restart_widgets);
}

static void __widget_flush_update_list(const char *pkgid, uid_t uid)
{
	__flush_pending_restart_list(pkgid, uid, &__update_widgets);
}

static int __on_app_dead(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	amd_app_status_h app_status = arg3;
	int pid = arg1;
	uid_t uid = arg2;
	widget_t *info;
	pid_t viewer_pid = amd_app_status_get_first_caller_pid(app_status);
	bool is_faulted = !amd_app_status_is_exiting(app_status);
	const char *appid = amd_app_status_get_appid(app_status);
	const char *pkgid = amd_app_status_get_pkgid(app_status);
	bool can_restart;
	bool is_widget;
	int r;

	is_widget = __widget_exist(pid, uid);
	if (!is_widget)
		return 0;

	can_restart = __check_restart(app_status);
	if (!can_restart || !is_faulted) {
		__widget_send_dead_signal(pid, uid, pkgid, is_faulted);
		return 0;
	}

	/*
	 * Screen info should be removed before send dead signal
	 * If not, _app_status_cleanup will send
	 * AUL_SCREEN_CONNECTOR_EVENT_TYPE_REMOVE
	 * event to the viewer and recreated instance with same
	 * instance id info will be removed by
	 * AUL_SCREEN_CONNECTOR_EVENT_TYPE_REMOVE event.
	 */
	amd_noti_send("widget.on_app_dead.restart",
			pid, (int)uid, NULL, NULL);
	if (amd_util_check_oom()) {
		info = __find_pending_restart_widget(appid, pid, uid,
				__oom_restart_widgets);
		if (info)
			return 0;

		r = __add_pending_restart_info(pid, uid, pkgid,
				&__oom_restart_widgets);
		if (r == 0) {
			LOGW("%s:%d is added on pending list", appid, pid);
			__widget_send_dead_signal(pid, uid, pkgid, is_faulted);
			return 0;
		}
	} else if (amd_appinfo_is_pkg_updating(pkgid)) {
		LOGW("%s:%d is updating", appid, pid);
		/*
		 * If widget package is in update process
		 * widget dead signal will be sent after
		 * update process is completed so that
		 * viewer can restart widget at that time.
		 */
		__widget_send_restart_signal(pid, uid, viewer_pid, pkgid,
				is_faulted);

		r = __add_pending_restart_info(pid, uid, pkgid,
				&__update_widgets);
		if (r == 0)
			return 0;

		__widget_send_dead_signal(pid, uid, pkgid, is_faulted);
		return 0;
	}

	__widget_send_restart_signal(pid, uid, viewer_pid, pkgid,
			is_faulted);
	__widget_send_dead_signal(pid, uid, pkgid, is_faulted);
	LOGW("Sent widget(%s:%d) dead signal", appid, pid);

	return 0;
}

static int __on_app_status_destroy(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	amd_app_status_h app_status = arg3;

	if (amd_app_status_get_app_type(app_status) == AMD_AT_WIDGET_APP) {
		__widget_cleanup(amd_app_status_get_pid(app_status),
				amd_app_status_get_uid(app_status),
				amd_app_status_get_first_caller_pid(app_status));
	}

	return 0;
}

static int __on_launching_widget(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	amd_request_h req = arg3;

	if (__widget_verify_cmd(req) < 0)
		return -1;

	return 0;
}

static int __on_package_update_end(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	uid_t uid = (uid_t)arg1;
	const char *pkgid = (const char *)arg3;

	__widget_flush_update_list(pkgid, uid);

	return 0;
}

static int __on_low_memory_normal(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	__widget_flush_oom_restart_list();

	return 0;
}

static void __widget_verify_instance(bundle *kb, int pid, uid_t uid)
{
	const char *operation;
	const char *instance_id;
	const char *widget_id;
	widget_t *widget;
	struct widget_status_info info;

	if (kb == NULL)
		return;

	operation = bundle_get_val(kb, AUL_K_WIDGET_OPERATION);
	if (operation == NULL)
		return;

	if (strcmp(operation, "create") != 0)
		return;

	widget_id = bundle_get_val(kb, AUL_K_WIDGET_ID);
	if (widget_id == NULL)
		return;

	instance_id = bundle_get_val(kb, AUL_K_WIDGET_INSTANCE_ID);
	if (instance_id == NULL)
		return;

	widget = __find_instance(widget_id, instance_id);
	if (widget)
		return;

	info.endpoint = bundle_get_val(kb, AUL_K_WIDGET_VIEWER);
	if (info.endpoint == NULL)
		return;

	info.widget_id = widget_id;
	info.instance_id = instance_id;
	info.pkg_id = NULL;
	info.is_fault = NULL;
	info.status = AUL_WIDGET_INSTANCE_EVENT_CREATE_ABORTED;
	info.pid = pid;
	info.uid = uid;

	LOGW("Send create aborted event %s:%s:%s",
			info.endpoint, info.widget_id, info.instance_id);
	__send_status_info(&info);
}

static int __on_launch_recv_timeout(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int pid = arg1;
	uid_t uid = (uid_t)arg2;

	__widget_verify_instance(data, pid, uid);

	return 0;
}

static int __on_launch_complete_start(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int pid = (int)arg1;
	amd_appinfo_h ai = (amd_appinfo_h)arg3;
	const char *comptype;
	const char *val;
	uid_t uid;

	comptype = amd_appinfo_get_value(ai, AMD_AIT_COMPTYPE);
	if (comptype && !strcmp(comptype, APP_TYPE_WIDGET)) {
		val = bundle_get_val(data, AUL_K_TARGET_UID);
		if (!val || !isdigit(*val))
			return 0;

		uid = strtoul(val, NULL, 10);
		__widget_pre_add(data, pid, uid);
	}


	return 0;
}

static int __on_launch_recv_error(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	int pid = arg1;
	uid_t uid = (uid_t)arg2;

	__widget_verify_instance(data, pid, uid);

	return 0;
}

static int __on_package_update_error(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	uid_t uid = (uid_t)arg1;
	const char *pkgid = (const char *)arg3;

	__widget_flush_update_list(pkgid, uid);

	return 0;
}

static int __widget_viewer_checker(amd_cynara_caller_info_h info, amd_request_h req)
{
	char *appid = NULL;
	const char *apptype;
	amd_appinfo_h appinfo;
	bundle *appcontrol = amd_request_get_bundle(req);

	if (!appcontrol) {
		LOGE("wrong argument");
		return AMD_CYNARA_RET_ERROR;
	}

	bundle_get_str(appcontrol, AUL_K_APPID, &appid);
	if (!appid) {
		LOGE("can not resolve appid. request denied.");
		return AMD_CYNARA_RET_ERROR;
	}

	appinfo = amd_appinfo_find(amd_request_get_target_uid(req), appid);
	if (!appinfo) {
		LOGE("can not resolve appinfo of %s. request denied.", appid);
		return AMD_CYNARA_RET_ERROR;

	}

	apptype = amd_appinfo_get_value(appinfo, AMD_AIT_COMPTYPE);
	if (!apptype) {
		LOGE("can not resolve apptype of %s. request denied.", appid);
		return AMD_CYNARA_RET_ERROR;
	}

	if (!strcmp(apptype, APP_TYPE_WIDGET) ||
			!strcmp(apptype, APP_TYPE_WATCH))
		return amd_cynara_simple_checker(info, req, PRIVILEGE_WIDGET_VIEWER);

	LOGE("illegal app type of request: %s - " \
			"only widget or watch apps are allowed", apptype);

	return AMD_CYNARA_RET_ERROR;
}

static int __appcontrol_sub_checker(amd_cynara_caller_info_h info, amd_request_h req)
{
	bundle *appcontrol;
	char *op = NULL;
	int ret;

	appcontrol = amd_request_get_bundle(req);
	if (!appcontrol)
		return AMD_CYNARA_RET_CONTINUE;

	ret = bundle_get_str(appcontrol, AUL_SVC_K_OPERATION, &op);
	if (ret != BUNDLE_ERROR_NONE)
		return AMD_CYNARA_RET_CONTINUE;

	if (!op || strcmp(op, AUL_SVC_OPERATION_LAUNCH_WIDGET))
		return AMD_CYNARA_RET_CONTINUE;

	return __widget_viewer_checker(info, req);
}

EXPORT int AMD_MOD_INIT(void)
{
	int r;

	LOGD("widget init");
	_widget_logger_init();
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

	amd_noti_listen("main.app_dead", __on_app_dead);
	amd_noti_listen("app_status.destroy", __on_app_status_destroy);
	amd_noti_listen("launch.prepare.widget", __on_launching_widget);
	amd_noti_listen("appinfo.package.update.end",  __on_package_update_end);
	amd_noti_listen("util.low_memory.normal", __on_low_memory_normal);
	amd_noti_listen("launch.recv.timeout", __on_launch_recv_timeout);
	amd_noti_listen("launch.complete.start", __on_launch_complete_start);
	amd_noti_listen("launch.recv.error", __on_launch_recv_error);
	amd_noti_listen("appinfo.package.update.error",
			__on_package_update_error);

	amd_cynara_sub_checker_add("appcontrol", __appcontrol_sub_checker);

	return 0;
}

EXPORT void AMD_MOD_FINI(void)
{
	LOGD("widget fini");

	if (__restart_widgets) {
		g_list_free_full(__restart_widgets,
				__destroy_restart_widget_info);
	}

	if (__update_widgets)
		g_list_free_full(__update_widgets, __free_widget);

	if (__widgets)
		g_list_free_full(__widgets, __free_widget);

	_widget_logger_fini();
}
