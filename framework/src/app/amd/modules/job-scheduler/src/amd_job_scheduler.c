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
#include <ctype.h>
#include <glib.h>
#include <gio/gio.h>
#include <aul.h>
#include <aul_cmd.h>
#include <aul_job_scheduler.h>
#include <bundle_internal.h>
#include <amd.h>

#include "amd_job_scheduler_private.h"

#define ARRAY_SIZE(x) ((sizeof(x)) / sizeof(x[0]))

struct job_s {
	char *id;
	pid_t pid;
	guint timer;
};

static GHashTable *__job_table;

static int __remove_job(const char *id, pid_t pid);

static void __destroy_job(gpointer data)
{
	struct job_s *job = (struct job_s *)data;

	if (job == NULL)
		return;

	if (job->timer)
		g_source_remove(job->timer);

	if (job->id)
		free(job->id);

	free(job);
}

static gboolean __job_timeout_handler(gpointer data)
{
	struct job_s *job = (struct job_s *)data;

	_D("job_id(%s), pid(%d)", job->id, job->pid);
	job->timer = 0;
	__remove_job(job->id, job->pid);

	return G_SOURCE_REMOVE;
}

static struct job_s *__create_job(const char *id, pid_t pid)
{
	struct job_s *job;

	job = malloc(sizeof(struct job_s));
	if (job == NULL) {
		_E("Out of memory");
		return NULL;
	}

	job->id = strdup(id);
	if (job->id == NULL) {
		_E("Out of memory");
		free(job);
		return NULL;
	}

	job->timer = g_timeout_add(5000, __job_timeout_handler, job);
	if (job->timer == 0) {
		_E("Failed to add timer");
		free(job->id);
		free(job);
		return NULL;
	}

	job->pid = pid;

	return job;
}

static struct job_s *__find_job(GList *list, const char *id)
{
	struct job_s *job;
	GList *iter;

	iter = list;
	while (iter) {
		job = (struct job_s *)iter->data;
		if (strcmp(job->id, id) == 0)
			return job;

		iter = iter->next;
	}

	return NULL;
}

static int __add_job(const char *id, pid_t pid)
{
	struct job_s *job;
	GList *list;

	list = (GList *)g_hash_table_lookup(__job_table, GINT_TO_POINTER(pid));
	if (list) {
		job = __find_job(list, id);
		if (job) {
			if (job->timer)
				g_source_remove(job->timer);

			job->timer = g_timeout_add(5000, __job_timeout_handler,
					job);
			if (job->timer == 0)
				return -1;
		} else {
			job = __create_job(id, pid);
			if (job == NULL)
				return -1;

			list = g_list_append(list, job);
			g_hash_table_replace(__job_table, GINT_TO_POINTER(pid),
					list);
		}
	} else {
		job = __create_job(id, pid);
		if (job == NULL)
			return -1;

		list = g_list_append(list, job);
		g_hash_table_insert(__job_table, GINT_TO_POINTER(pid), list);
	}
	amd_suspend_remove_timer(pid);

	return 0;
}

static int __remove_job(const char *id, pid_t pid)
{
	struct job_s *job;
	GList *list;
	amd_app_status_h app_status;
	int status;

	list = (GList *)g_hash_table_lookup(__job_table, GINT_TO_POINTER(pid));
	if (list == NULL)
		return -1;

	job = __find_job(list, id);
	if (job == NULL)
		return -1;

	list = g_list_remove(list, job);
	if (list == NULL) {
		g_hash_table_remove(__job_table, GINT_TO_POINTER(pid));
		app_status = amd_app_status_find_by_pid(pid);
		if (app_status) {
			status = amd_app_status_get_status(app_status);
			if (status != STATUS_DYING)
				amd_suspend_add_timer(pid);
		}
	} else {
		g_hash_table_replace(__job_table, GINT_TO_POINTER(pid), list);
	}

	__destroy_job(job);

	return 0;
}

static int __remove_all_jobs(pid_t pid)
{
	GList *list;

	list = (GList *)g_hash_table_lookup(__job_table, GINT_TO_POINTER(pid));
	if (list == NULL)
		return -1;

	g_hash_table_remove(__job_table, GINT_TO_POINTER(pid));
	g_list_free_full(list, __destroy_job);

	return 0;
}

static int __on_app_status_cleanup(const char *msg, int arg1, int arg2,
		void *arg3, bundle *data)
{
	amd_app_status_h app_status = (amd_app_status_h)arg3;
	pid_t pid = amd_app_status_get_pid(app_status);

	__remove_all_jobs(pid);

	return 0;
}

static int __dispatch_job_status_update(amd_request_h req)
{
	bundle *b = amd_request_get_bundle(req);
	pid_t pid = amd_request_get_pid(req);
	const char *job_id;
	const char *job_status_str;
	aul_job_status_e job_status;
	int r;

	if (b == NULL) {
		_E("Invalid parameter");
		return -1;
	}

	job_id = bundle_get_val(b, AUL_K_JOB_ID);
	if (job_id == NULL) {
		_E("Failed to get job - pid(%d)", pid);
		return -1;
	}

	job_status_str = bundle_get_val(b, AUL_K_JOB_STATUS);
	if (job_status_str == NULL) {
		_E("Failed to get job(%s) status", job_id);
		return -1;
	}

	if (!isdigit(*job_status_str)) {
		_E("Invalid job(%s) status(%s)", job_id, job_status_str);
		return -1;
	}

	job_status = strtoul(job_status_str, NULL, 10);
	switch (job_status) {
	case JOB_STATUS_START:
		r = __add_job(job_id, pid);
		if (r < 0) {
			_E("Failed to add job(%s)", job_id);
			return -1;
		}
		break;
	case JOB_STATUS_STOPPED:
	case JOB_STATUS_FINISHED:
		r = __remove_job(job_id, pid);
		if (r < 0) {
			_W("Failed to remove job(%s)", job_id);
			return -1;
		}
		break;
	default:
		_W("Unknown job status(%u)", job_status);
		break;
	}

	_D("job_id(%s), job_status(%u), pid(%d)", job_id, job_status, pid);

	return 0;
}

static amd_request_cmd_dispatch __dispatch_table[] = {
	{
		.cmd = JOB_STATUS_UPDATE,
		.callback = __dispatch_job_status_update
	},
};

EXPORT int AMD_MOD_INIT(void)
{
	int r;

	_D("job scheduler init");

	r = amd_request_register_cmds(__dispatch_table,
			ARRAY_SIZE(__dispatch_table));
	if (r < 0) {
		_E("Failed to register cmds");
		return -1;
	}

	__job_table = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (__job_table == NULL) {
		_E("Failed to create job table");
		return -1;
	}

	amd_noti_listen("app_status.cleanup", __on_app_status_cleanup);

	return 0;
}

static gboolean __foreach_remove_cb(gpointer key, gpointer value,
		gpointer data)
{
	pid_t pid = GPOINTER_TO_INT(key);
	GList *list = (GList *)value;

	_D("pid(%d)", pid);
	g_list_free_full(list, __destroy_job);

	return TRUE;
}

EXPORT void AMD_MOD_FINI(void)
{
	_D("job scheduler finish");

	if (__job_table) {
		g_hash_table_foreach_remove(__job_table, __foreach_remove_cb,
				NULL);
		g_hash_table_destroy(__job_table);
	}
}
