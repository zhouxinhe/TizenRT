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
#include <bundle.h>
#include <glib.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_noti.h"

static GList *__listeners;

struct listener_s {
	char *msg;
	noti_cb callback;
};

int _noti_send(const char *msg, int arg1, int arg2, void *arg3, bundle *data)
{
	struct listener_s *listener;
	GList *i = __listeners;
	int ret;

	if (!msg)
		return -1;

	while (i) {
		listener = (struct listener_s *)i->data;
		if (listener->msg && !strcmp(listener->msg, msg)) {
			if (listener->callback) {
				ret = listener->callback(msg, arg1, arg2,
						arg3, data);
				if (ret != NOTI_CONTINUE)
					return -1;
			}
		}

		i = g_list_next(i);
	}

	return 0;
}

int _noti_listen(const char *msg, noti_cb callback)
{
	struct listener_s *l;

	l = calloc(1, sizeof(struct listener_s));
	if (!l) {
		_E("Out of memory");
		return -1;
	}

	l->msg = strdup(msg);
	if (!l->msg) {
		_E("Out of memory");
		free(l);
		return -1;
	}

	l->callback = callback;

	__listeners = g_list_append(__listeners, l);

	return 0;
}

int _noti_init(void)
{
	return 0;
}

static void __free_listener(gpointer data)
{
	struct listener_s *listener = data;

	free(listener->msg);
	free(listener);
}

void _noti_fini(void)
{
	g_list_free_full(__listeners, __free_listener);
	__listeners = NULL;
}
