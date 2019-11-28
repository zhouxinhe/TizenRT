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
#include <string.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <glib.h>
#include <gio/gio.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_inotify.h"

#define INOTIFY_BUF (1024 * ((sizeof(struct inotify_event)) + 16))

struct inotify_watch_info_s {
	int wd;
	inotify_watch_cb cb;
	void *data;
};

struct inotify_info {
	int fd;
	GIOChannel *io;
	guint id;
	bool initialized;
};

static struct inotify_info __inotify;
static GList *__watch_list;
static GHashTable *__wd_table;

static void __insert_wd_info(struct inotify_watch_info_s *info)
{
	GList *list;

	list = (GList *)g_hash_table_lookup(__wd_table,
			GINT_TO_POINTER(info->wd));
	if (list == NULL) {
		list = g_list_append(list, info);
		g_hash_table_insert(__wd_table,
				GINT_TO_POINTER(info->wd), list);
	} else {
		list = g_list_append(list, info);
		g_hash_table_replace(__wd_table,
				GINT_TO_POINTER(info->wd), list);
	}
}

static void __delete_wd_info(struct inotify_watch_info_s *info)
{
	GList *list;

	list = (GList *)g_hash_table_lookup(__wd_table,
			GINT_TO_POINTER(info->wd));
	if (list == NULL)
		return;

	list = g_list_remove(list, info);
	if (list == NULL) {
		g_hash_table_remove(__wd_table,
				GINT_TO_POINTER(info->wd));
		inotify_rm_watch(__inotify.fd, info->wd);
	} else {
		g_hash_table_replace(__wd_table,
				GINT_TO_POINTER(info->wd), list);
	}
}

static void __destroy_inotify_watch_info(gpointer data)
{
	struct inotify_watch_info_s *info = (struct inotify_watch_info_s *)data;

	if (info == NULL)
		return;

	__delete_wd_info(info);
	free(info);
}

static struct inotify_watch_info_s *__create_inotify_watch_info(
		const char *path, uint32_t mask, inotify_watch_cb cb,
		void *data)
{
	struct inotify_watch_info_s *info;

	info = calloc(1, sizeof(struct inotify_watch_info_s));
	if (info == NULL) {
		_E("Out of memory");
		return NULL;
	}

	info->wd = inotify_add_watch(__inotify.fd, path, mask);
	if (info->wd < 0) {
		_E("Failed to add inotify watch, path(%s), errno(%d)",
				path, errno);
		free(info);
		return NULL;
	}

	info->cb = cb;
	info->data = data;

	__insert_wd_info(info);

	return info;
}

static void __fini_inotify(void)
{
	if (__inotify.id) {
		g_source_remove(__inotify.id);
		__inotify.id = 0;
	}

	if (__inotify.io) {
		g_io_channel_unref(__inotify.io);
		__inotify.io = NULL;
	}

	if (__inotify.fd > 0) {
		close(__inotify.fd);
		__inotify.fd = 0;
	}

	__inotify.initialized = false;
}

static gboolean __inotify_watch_cb(GIOChannel *io, GIOCondition cond,
		gpointer data)
{
	char buf[INOTIFY_BUF];
	ssize_t len;
	int i = 0;
	struct inotify_event *e;
	int fd = g_io_channel_unix_get_fd(io);
	inotify_watch_info_h info;
	GList *iter;

	len = read(fd, buf, sizeof(buf));
	if (len < 0) {
		_W("Failed to read from a inotify file descriptor");
		return G_SOURCE_CONTINUE;
	}

	while (i < len) {
		e = (struct inotify_event *)&buf[i];
		if (e->len) {
			iter = __watch_list;
			while (iter) {
				info = (inotify_watch_info_h)iter->data;
				iter = g_list_next(iter);
				if (info->wd == e->wd &&
					!info->cb(e->name, info->data)) {
					__watch_list = g_list_remove(
							__watch_list, info);
					__destroy_inotify_watch_info(info);
				}
			}
		}

		i += offsetof(struct inotify_event, name) + e->len;
		if (i >= INOTIFY_BUF)
			break;
	}

	return G_SOURCE_CONTINUE;
}

static int __init_inotify(void)
{
	GIOCondition cond = G_IO_IN | G_IO_PRI | G_IO_ERR | G_IO_HUP;

	if (__inotify.initialized)
		return 0;

	__wd_table = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (__wd_table == NULL) {
		_E("Failed to create wd table");
		return -1;
	}

	__inotify.fd = inotify_init1(IN_CLOEXEC);
	if (__inotify.fd < 0) {
		_E("Failed to initialize inotify");
		return -1;
	}

	__inotify.io = g_io_channel_unix_new(__inotify.fd);
	if (__inotify.io == NULL) {
		_E("Failed to create a new GIOChannel");
		__fini_inotify();
		return -1;
	}

	__inotify.id = g_io_add_watch(__inotify.io, cond,
			__inotify_watch_cb, NULL);
	if (__inotify.id == 0) {
		_E("Failed to add GIOChannel watch");
		__fini_inotify();
		return -1;
	}

	__inotify.initialized = true;

	return 0;
}

inotify_watch_info_h _inotify_add_watch(const char *path, uint32_t mask,
		inotify_watch_cb callback, void *data)
{
	struct inotify_watch_info_s *info;

	if (path == NULL || callback == NULL) {
		_E("Invalid parameter");
		return NULL;
	}

	if (__init_inotify() < 0)
		return NULL;

	info = __create_inotify_watch_info(path, mask, callback, data);
	if (info == NULL)
		return NULL;

	__watch_list = g_list_append(__watch_list, info);

	return info;
}

void _inotify_rm_watch(inotify_watch_info_h handle)
{
	if (handle == NULL)
		return;

	__watch_list = g_list_remove(__watch_list, handle);
	__destroy_inotify_watch_info(handle);
}

int _inotify_init(void)
{
	_D("inotify init");

	__init_inotify();

	return 0;
}

void _inotify_fini(void)
{
	_D("inotify fini");

	if (__watch_list)
		g_list_free_full(__watch_list, __destroy_inotify_watch_info);

	if (__wd_table)
		g_hash_table_destroy(__wd_table);

	__fini_inotify();
}
