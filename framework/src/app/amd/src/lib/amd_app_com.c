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
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <aul.h>
#include <aul_cmd.h>
#include <aul_app_com.h>
#include <aul_sock.h>

#include "amd_util.h"
#include "amd_app_com.h"
#include "amd_request.h"
#include "amd_cynara.h"

struct endpoint_info {
	char *endpoint;
	unsigned int propagate;
	char *privilege;
	GList *clients;
};

struct client_info {
	int pid;
	uid_t uid;
	char *filter;
	struct endpoint_info *endpoint;
};

static GHashTable *cpid_tbl;
static GHashTable *endpoint_tbl;

static void __remove_client(struct endpoint_info *info, int cpid);

static void __free_endpoint(struct endpoint_info *info)
{
	if (!info)
		return;

	if (info->endpoint)
		g_free(info->endpoint);

	if (info->privilege)
		g_free(info->privilege);

	if (info->clients)
		g_list_free(info->clients);

	g_free(info);
}

static void __remove_cpid(gpointer key, gpointer value, gpointer user_data)
{
	int pid = GPOINTER_TO_INT(key);
	struct endpoint_info *info;
	GList *client_list = (GList *)value;

	while (client_list) {
		info = (struct endpoint_info *)client_list->data;
		__remove_client(info, pid);
		client_list = client_list->next;
	}
	g_list_free((GList *)value);
}

static int __app_com_add_endpoint(const char *endpoint, unsigned int propagate,
		const char *assoc_priv)
{
	struct endpoint_info *info;

	info = g_hash_table_lookup(endpoint_tbl, endpoint);
	if (info) {
		_E("endpoint already exists.");
		return AUL_APP_COM_R_ERROR_ENDPOINT_ALREADY_EXISTS;
	}

	_D("endpoint=%s propagate=%d assoc_priv=%s",
			endpoint, propagate, assoc_priv);

	info = (struct endpoint_info *)g_malloc0(sizeof(struct endpoint_info));
	if (info == NULL) {
		_E("out of memory");
		return AUL_APP_COM_R_ERROR_OUT_OF_MEMORY;
	}

	info->endpoint = g_strdup(endpoint);
	if (info->endpoint == NULL) {
		_E("Out of memory");
		g_free(info);
		return AUL_APP_COM_R_ERROR_OUT_OF_MEMORY;
	}
	info->propagate = propagate;
	info->clients = NULL;

	if (assoc_priv) {
		info->privilege = g_strdup(assoc_priv);
		if (info->privilege == NULL) {
			_E("Out of memory");
			g_free(info->endpoint);
			g_free(info);
			return AUL_APP_COM_R_ERROR_OUT_OF_MEMORY;
		}
	} else {
		info->privilege = NULL;
	}

	g_hash_table_insert(endpoint_tbl, info->endpoint, info);

	return AUL_APP_COM_R_ERROR_OK;
}

static int __app_com_remove_endpoint(const char *endpoint)
{
	struct endpoint_info *info;

	info = g_hash_table_lookup(endpoint_tbl, endpoint);
	if (!info) {
		_D("endpoint not exists");
		return AUL_APP_COM_R_ERROR_UNKNOWN_ENDPOINT;
	}

	if (info->clients != NULL) {
		_D("client active");
		return AUL_APP_COM_R_ERROR_CLIENT_REMAINING;
	}

	g_hash_table_remove(endpoint_tbl, endpoint);
	__free_endpoint(info);

	return AUL_APP_COM_R_ERROR_OK;
}

static struct client_info *__add_client(struct endpoint_info *info,
		const char *filter, int pid, uid_t uid)
{
	GList *client_list;
	struct client_info *c;

	c = (struct client_info *)g_malloc0(sizeof(struct client_info));
	if (c == NULL) {
		_E("out of memory");
		return NULL;
	}

	c->endpoint = info;
	c->pid = pid;
	c->uid = uid;
	if (filter) {
		c->filter = g_strdup(filter);
		if (c->filter == NULL) {
			_E("Out of memory");
			g_free(c);
			return NULL;
		}
	} else {
		c->filter = NULL;
	}

	info->clients = g_list_append(info->clients, c);
	client_list = g_hash_table_lookup(cpid_tbl, GINT_TO_POINTER(pid));
	if (client_list == NULL) {
		client_list = g_list_append(client_list, info);
		g_hash_table_insert(cpid_tbl, GINT_TO_POINTER(pid),
				client_list);
	} else {
		client_list = g_list_append(client_list, info);
	}

	return c;
}

static int __app_com_join(const char *endpoint, int cpid, const char *filter,
		uid_t uid)
{
	struct endpoint_info *info;

	info = g_hash_table_lookup(endpoint_tbl, endpoint);
	if (!info) {
		_E("endpoint not exists: %s", endpoint);
		return AUL_APP_COM_R_ERROR_UNKNOWN_ENDPOINT;
	}

	_D("endpoint=%s cpid=%d filter=%s uid=%d", endpoint, cpid, filter, uid);

	if (__add_client(info, filter, cpid, uid) == NULL)
		return AUL_APP_COM_R_ERROR_OUT_OF_MEMORY;

	return AUL_APP_COM_R_ERROR_OK;
}

const char *_app_com_get_privilege(const char *endpoint)
{
	struct endpoint_info *info;

	info = g_hash_table_lookup(endpoint_tbl, endpoint);
	if (!info) {
		_E("endpoint not exists: %s", endpoint);
		return NULL;
	}

	return info->privilege;
}

static int __check_filter(const char *filter, int cpid, int rpid, bundle *b)
{
	/* TODO */
	return 0;
}

int _app_com_send(const char *endpoint, int cpid, bundle *envelope, uid_t uid)
{
	struct endpoint_info *info;
	GList *client_head;
	struct client_info *client;
	int ret;
	int result = AUL_APP_COM_R_OK;

	info = g_hash_table_lookup(endpoint_tbl, endpoint);
	if (!info) {
		_E("endpoint not exists: %s", endpoint);
		return AUL_APP_COM_R_ERROR_UNKNOWN_ENDPOINT;
	}

	/* TODO delete internal keys */

	_D("endpoint=%s cpid=%d", endpoint, cpid);

	bundle_add_str(envelope, AUL_K_COM_ENDPOINT, endpoint);
	bundle_add_byte(envelope, AUL_K_COM_RESULT, &result, sizeof(result));

	client_head = info->clients;
	while (client_head) {
		client = (struct client_info *)client_head->data;
		client_head = client_head->next;
		if (client == NULL)
			continue;
		if (client->pid == cpid)
			continue;
		if (client->uid >= REGULAR_UID_MIN && client->uid != uid)
			continue;

		if (client->filter) {
			ret = __check_filter(client->filter, cpid, client->pid,
					envelope);
			if (ret < 0)
				continue;
		}

		ret = aul_sock_send_bundle(client->pid, client->uid,
				APP_COM_MESSAGE, envelope, AUL_SOCK_NOREPLY);
		if (ret < 0) {
			_E("failed to send message pid(%d), uid(%d), ret(%d)",
					client->pid, client->uid, ret);
		}
	}

	return AUL_APP_COM_R_ERROR_OK;
}

static void __remove_client(struct endpoint_info *info, int cpid)
{
	GList *client_head;
	struct client_info *client;

	if (info == NULL)
		return;

	client_head = info->clients;
	while (client_head) {
		client = (struct client_info *)client_head->data;
		client_head = client_head->next;
		if (client && client->pid == cpid) {
			info->clients = g_list_remove(info->clients, client);
			if (client->filter)
				g_free(client->filter);

			g_free(client);
		}
	}

	if (info->clients == NULL) {
		g_hash_table_remove(endpoint_tbl, info->endpoint);
		_D("endpoint removed: %s", info->endpoint);
		__free_endpoint(info);
	}
}

static int __app_com_leave(const char *endpoint, int cpid)
{
	struct endpoint_info *info;
	GList *endpoint_head;

	info = g_hash_table_lookup(endpoint_tbl, endpoint);
	if (!info) {
		_E("endpoint not exists: %s", endpoint);
		return AUL_APP_COM_R_ERROR_UNKNOWN_ENDPOINT;
	}

	endpoint_head = g_hash_table_lookup(cpid_tbl, GINT_TO_POINTER(cpid));
	if (endpoint_head) {
		endpoint_head = g_list_remove(endpoint_head, info);
		if (endpoint_head == NULL) {
			g_hash_table_remove(cpid_tbl, GINT_TO_POINTER(cpid));
		} else {
			g_hash_table_replace(cpid_tbl, GINT_TO_POINTER(cpid),
					endpoint_head);
		}
	}
	__remove_client(info, cpid);

	return AUL_APP_COM_R_ERROR_OK;
}

int _app_com_client_remove(int cpid)
{
	GList *client_list;
	struct endpoint_info *info;
	GList *client_head;

	client_list = g_hash_table_lookup(cpid_tbl, GINT_TO_POINTER(cpid));
	if (client_list == NULL)
		return AUL_APP_COM_R_OK;

	client_head = g_list_first(client_list);
	while (client_head) {
		info = (struct endpoint_info *)client_head->data;
		client_head = g_list_next(client_head);
		if (info) {
			client_list = g_list_remove(client_list, info);
			__remove_client(info, cpid);
		}
	}

	g_hash_table_remove(cpid_tbl, GINT_TO_POINTER(cpid));

	return AUL_APP_COM_R_ERROR_OK;
}

bool _app_com_endpoint_exists(const char *endpoint)
{
	return g_hash_table_contains(endpoint_tbl, endpoint);
}

static int __dispatch_app_com_create(request_h req)
{
	bundle *kb;
	int ret;
	size_t propagate_size;
	unsigned int propagate = 0;
	const char *privilege;
	const char *endpoint;
	unsigned int *prop;

	kb = _request_get_bundle(req);
	if (kb == NULL)
		return -1;

	endpoint = bundle_get_val(kb, AUL_K_COM_ENDPOINT);
	if (endpoint == NULL) {
		_request_send_result(req, AUL_APP_COM_R_ERROR_FATAL_ERROR);
		return 0;
	}

	privilege = bundle_get_val(kb, AUL_K_COM_PRIVILEGE);
	if (!privilege) {
		/* privilege is not mandatory so far */
		_D("non-privileged endpoint: %s", endpoint);
	}

	ret = bundle_get_byte(kb, AUL_K_COM_PROPAGATE, (void **)&prop,
			&propagate_size);
	if (ret == 0)
		propagate = *prop;

	_D("endpoint: %s propagate: %x privilege: %s",
			endpoint, propagate, privilege);

	ret = __app_com_add_endpoint(endpoint, propagate, privilege);
	if (ret == AUL_APP_COM_R_ERROR_OK ||
			ret == AUL_APP_COM_R_ERROR_ENDPOINT_ALREADY_EXISTS) {
		ret = __app_com_join(endpoint, getpgid(_request_get_pid(req)), NULL,
				_request_get_uid(req));
		if (ret == AUL_APP_COM_R_ERROR_ILLEGAL_ACCESS) {
			_E("illegal access: remove endpoint");
			__app_com_remove_endpoint(endpoint);
		}
	}

	_request_send_result(req, ret);
	return 0;
}

static int __dispatch_app_com_join(request_h req)
{
	bundle *kb;
	int ret;
	const char *endpoint;
	const char *filter;

	kb = _request_get_bundle(req);
	if (kb == NULL)
		return -1;

	endpoint = bundle_get_val(kb, AUL_K_COM_ENDPOINT);
	if (endpoint == NULL) {
		bundle_free(kb);
		_request_send_result(req, AUL_APP_COM_R_ERROR_FATAL_ERROR);
		return 0;
	}

	filter = bundle_get_val(kb, AUL_K_COM_FILTER);

	ret = __app_com_join(endpoint, getpgid(_request_get_pid(req)), filter,
			_request_get_uid(req));

	_request_send_result(req, ret);

	return 0;
}

static int __dispatch_app_com_send(request_h req)
{
	bundle *kb;
	int ret;
	const char *endpoint;
	int sender_pid = _request_get_pid(req);
	char sender_pid_str[MAX_PID_STR_BUFSZ];
	uid_t sender_uid = _request_get_uid(req);

	kb = _request_get_bundle(req);
	if (kb == NULL)
		return -1;

	snprintf(sender_pid_str, MAX_PID_STR_BUFSZ, "%d", sender_pid);
	bundle_del(kb, AUL_K_COM_SENDER_PID);
	bundle_add(kb, AUL_K_COM_SENDER_PID, sender_pid_str);
	endpoint = bundle_get_val(kb, AUL_K_COM_ENDPOINT);
	if (endpoint == NULL) {
		_request_send_result(req, AUL_APP_COM_R_ERROR_FATAL_ERROR);
		return 0;
	}

	ret = _app_com_send(endpoint, getpgid(sender_pid), kb, sender_uid);
	_request_send_result(req, ret);

	return 0;
}

static int __dispatch_app_com_leave(request_h req)
{
	bundle *kb;
	int ret;
	const char *endpoint;

	kb = _request_get_bundle(req);
	if (kb == NULL)
		return -1;

	endpoint = bundle_get_val(kb, AUL_K_COM_ENDPOINT);
	if (endpoint == NULL) {
		_request_send_result(req, AUL_APP_COM_R_ERROR_FATAL_ERROR);
		return 0;
	}

	ret = __app_com_leave(endpoint, getpgid(_request_get_pid(req)));
	_request_send_result(req, ret);

	return 0;
}

static request_cmd_dispatch __dispatch_table[] = {
	{
		.cmd = APP_COM_CREATE,
		.callback = __dispatch_app_com_create
	},
	{
		.cmd = APP_COM_JOIN,
		.callback = __dispatch_app_com_join
	},
	{
		.cmd = APP_COM_SEND,
		.callback = __dispatch_app_com_send
	},
	{
		.cmd = APP_COM_LEAVE,
		.callback = __dispatch_app_com_leave
	},
};

static int __com_create_checker(caller_info_h info, request_h req,
		void *data)
{
	char *privilege = NULL;
	bundle *kb = _request_get_bundle(req);

	bundle_get_str(kb, AUL_K_COM_PRIVILEGE, &privilege);
	if (!privilege)
		return 0;

	return _cynara_simple_checker(info, req, privilege);
}

static int __com_join_checker(caller_info_h info, request_h req,
		void *data)
{
	char *endpoint = NULL;
	const char *privilege;
	bundle *kb = _request_get_bundle(req);

	bundle_get_str(kb, AUL_K_COM_ENDPOINT, &endpoint);
	if (!endpoint)
		return -1;

	privilege = _app_com_get_privilege(endpoint);
	if (!privilege)
		return 0;

	return _cynara_simple_checker(info, req, (void *)privilege);
}

static cynara_checker __cynara_checkers[] = {
	{
		.cmd = APP_COM_JOIN,
		.checker = __com_join_checker,
		.data = NULL
	},
	{
		.cmd = APP_COM_CREATE,
		.checker = __com_create_checker,
		.data = NULL
	},
};

int _app_com_broker_init(void)
{
	int r;

	if (!endpoint_tbl) {
		endpoint_tbl = g_hash_table_new(g_str_hash, g_str_equal);
		if (endpoint_tbl == NULL) {
			_E("out of memory");
			return -1;
		}
	}

	if (!cpid_tbl) {
		cpid_tbl = g_hash_table_new(g_direct_hash, g_direct_equal);
		if (cpid_tbl == NULL) {
			_E("out of memory");
			return -1;
		}
	}

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

int _app_com_broker_fini(void)
{
	if (cpid_tbl) {
		g_hash_table_foreach(cpid_tbl, __remove_cpid, NULL);
		g_hash_table_destroy(cpid_tbl);
		cpid_tbl = NULL;
	}

	if (endpoint_tbl) {
		g_hash_table_destroy(endpoint_tbl);
		endpoint_tbl = NULL;
	}

	return 0;
}
