/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>

#include "launchpad-private.h"
#include "launcher_info.h"

#define FREE_AND_NULL(x) do { \
	if (x) { \
		free(x); \
		x = NULL; \
	} \
} while (0)

#define TAG_LAUNCHER	"[LAUNCHER]"
#define TAG_NAME	"NAME"
#define TAG_EXE		"EXE"
#define TAG_APP_TYPE	"APP_TYPE"
#define TAG_EXTRA_ARG	"EXTRA_ARG"

struct launcher_info_s {
	char *name;
	char *exe;
	GList *app_types;
	GList *extra_args;
};

static struct launcher_info_s *__create_launcher_info(void)
{
	struct launcher_info_s *info;

	info = calloc(1, sizeof(struct launcher_info_s));
	if (info == NULL) {
		LOGE("Out of memory");
		return NULL;
	}

	return info;
}

static void __destroy_launcher_info(gpointer data)
{
	struct launcher_info_s *info = (struct launcher_info_s *)data;

	if (info == NULL)
		return;

	if (info->extra_args)
		g_list_free_full(info->extra_args, free);
	if (info->app_types)
		g_list_free_full(info->app_types, free);
	if (info->exe)
		free(info->exe);
	if (info->name)
		free(info->name);
	free(info);
}

static void __parse_app_types(struct launcher_info_s *info, char *line)
{
	char *token;
	char *saveptr = NULL;

	token = strtok_r(line, " |\t\r\n", &saveptr);
	while (token) {
		info->app_types = g_list_append(info->app_types, strdup(token));
		token = strtok_r(NULL, " |\t\r\n", &saveptr);
	}
}

static GList *__parse_file(GList *list, const char *path)
{
	FILE *fp;
	char buf[LINE_MAX];
	char *tok1 = NULL;
	char *tok2 = NULL;
	struct launcher_info_s *info = NULL;

	fp = fopen(path, "rt");
	if (fp == NULL)
		return list;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		FREE_AND_NULL(tok1);
		FREE_AND_NULL(tok2);
		sscanf(buf, "%ms %ms", &tok1, &tok2);
		if (tok1 && strcasecmp(TAG_LAUNCHER, tok1) == 0) {
			if (info) {
				LOGD("name: %s, exe: %s", info->name, info->exe);
				list = g_list_append(list, info);
			}

			info = __create_launcher_info();
			if (info == NULL)
				break;

			continue;
		}

		if (!tok1 || !tok2)
			continue;
		if (tok1[0] == '\0' || tok2[0] == '\0' || tok1[0] == '#')
			continue;
		if (info == NULL)
			continue;

		if (strcasecmp(TAG_NAME, tok1) == 0) {
			info->name = strdup(tok2);
			if (info->name == NULL) {
				LOGE("Out of memory");
				__destroy_launcher_info(info);
				info = NULL;
				break;
			}
		} else if (strcasecmp(TAG_EXE, tok1) == 0) {
			info->exe = strdup(tok2);
			if (info->exe == NULL) {
				LOGE("Out of memory");
				__destroy_launcher_info(info);
				info = NULL;
				break;
			}
			if (access(info->exe, F_OK | X_OK) != 0) {
				LOGE("Failed to access %s", info->exe);
				__destroy_launcher_info(info);
				info = NULL;
			}
		} else if (strcasecmp(TAG_APP_TYPE, tok1) == 0) {
			__parse_app_types(info, &buf[strlen(tok1)]);
			if (info->app_types == NULL) {
				LOGE("app_types is NULL");
				__destroy_launcher_info(info);
				info = NULL;
				break;
			}
		} else if (strcasecmp(TAG_EXTRA_ARG, tok1) == 0) {
			info->extra_args = g_list_append(info->extra_args,
					strdup(tok2));
		}
	}
	fclose(fp);

	if (info) {
		LOGD("name: %s, exe: %s", info->name, info->exe);
		list = g_list_append(list, info);
	}

	if (tok1)
		free(tok1);
	if (tok2)
		free(tok2);

	return list;
}

GList *_launcher_info_load(const char *path)
{
	DIR *dp;
	struct dirent *dentry = NULL;
	GList *list = NULL;
	char buf[PATH_MAX];
	char *ext;

	if (path == NULL)
		return NULL;

	dp = opendir(path);
	if (dp == NULL)
		return NULL;

	while ((dentry = readdir(dp)) != NULL) {
		if (dentry->d_name[0] == '.')
			continue;

		ext = strrchr(dentry->d_name, '.');
		if (ext && strcmp(ext, ".launcher") == 0) {
			snprintf(buf, sizeof(buf), "%s/%s",
					path, dentry->d_name);
			list = __parse_file(list, buf);
		}
	}
	closedir(dp);

	return list;
}

void _launcher_info_unload(GList *info)
{
	if (info == NULL)
		return;

	g_list_free_full(info, __destroy_launcher_info);
}

static int __comp_str(gconstpointer a, gconstpointer b)
{
	if (a == NULL || b == NULL)
		return -1;

	return strcmp(a, b);
}

static int __comp_app_type(gconstpointer a, gconstpointer b)
{
	struct launcher_info_s *info = (struct launcher_info_s *)a;

	if (info == NULL || info->app_types == NULL || b == NULL)
		return -1;

	if (g_list_find_custom(info->app_types, b, __comp_str))
		return 0;

	return -1;
}

launcher_info_h _launcher_info_find(GList *info_list, const char *app_type)
{
	GList *list;

	if (info_list == NULL || app_type == NULL)
		return NULL;

	list = g_list_find_custom(info_list, app_type, __comp_app_type);
	if (list == NULL)
		return NULL;

	return (launcher_info_h)list->data;
}

const char *_launcher_info_get_exe(launcher_info_h info)
{
	if (info == NULL)
		return NULL;

	return info->exe;
}

GList *_launcher_info_get_extra_args(launcher_info_h info)
{
	if (info == NULL)
		return NULL;

	return info->extra_args;
}
