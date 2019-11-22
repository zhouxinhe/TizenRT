/*
 * Copyright (c) 2011 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>

#include <app_common_internal.h>

typedef struct _app_finalizer_s_ {
	app_finalizer_cb callback;
	void *data;
	struct _app_finalizer_s_ *next;
} app_finalizer_s;

typedef app_finalizer_s *app_finalizer_h;

static app_finalizer_s finalizer_head = {
	.callback = NULL,
	.data = NULL,
	.next = NULL
};

int app_finalizer_add(app_finalizer_cb callback, void *data)
{
	app_finalizer_h finalizer_tail = &finalizer_head;
	app_finalizer_h finalizer_new;

	finalizer_new = malloc(sizeof(app_finalizer_s));
	if (finalizer_new == NULL)
		return app_error(APP_ERROR_OUT_OF_MEMORY, __FUNCTION__, NULL);

	finalizer_new->callback = callback;
	finalizer_new->data = data;
	finalizer_new->next = NULL;

	while (finalizer_tail->next)
		finalizer_tail = finalizer_tail->next;

	finalizer_tail->next = finalizer_new;

	return APP_ERROR_NONE;
}

int app_finalizer_remove(app_finalizer_cb callback)
{
	app_finalizer_h finalizer_node = &finalizer_head;

	while (finalizer_node->next) {
		if (finalizer_node->next->callback == callback) {
			app_finalizer_h removed_node = finalizer_node->next;
			finalizer_node->next = removed_node->next;
			free(removed_node);
			return APP_ERROR_NONE;
		}

		finalizer_node = finalizer_node->next;
	}

	return APP_ERROR_INVALID_PARAMETER;
}

void app_finalizer_execute(void)
{
	app_finalizer_h finalizer_node = &finalizer_head;
	app_finalizer_h finalizer_executed;
	app_finalizer_cb finalizer_cb = NULL;

	if (finalizer_node)
		finalizer_node = finalizer_node->next;

	while (finalizer_node) {
		finalizer_cb = finalizer_node->callback;

		finalizer_cb(finalizer_node->data);

		finalizer_executed = finalizer_node;

		finalizer_node = finalizer_node->next;

		free(finalizer_executed);
	}

	finalizer_head.next = NULL;
}

