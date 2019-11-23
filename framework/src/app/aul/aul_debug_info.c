/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All rights reserved.
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
 *
 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <glib.h>
#include <bundle_internal.h>

#include "aul.h"
#include "aul_api.h"
#include "aul_util.h"
#include "aul_debug_info.h"

#define PATH_AUL                "/usr/share/aul"
#define TAG_DEBUGGER            "[DEBUGGER]"
#define TAG_NAME                "NAME"
#define TAG_EXTRA_KEY           "EXTRA_KEY"
#define TAG_EXTRA_ENV           "EXTRA_ENV"
#define TAG_UNLINK              "UNLINK"
#define TAG_ATTACH              "ATTACH"
#define TAG_LAST_EXTRA_KEY      "LAST_EXTRA_KEY"
#define TAG_DEFAULT_OPT         "DEFAULT_OPT"

#define FREE_AND_NULL(x) do {   \
        if (x) {                \
                free(x);        \
                x = NULL;       \
        }                       \
} while (0)

struct debugger_info_s {
	char *name;
	char *attach;
	GList *extra_key_list;
	GList *extra_env_list;
	GList *unlink_list;
	GList *last_extra_key_list;
	GList *default_opt_list;
};

struct debug_info_s {
	bool initialized;
	GList *debugger_list;
};

struct cb_data_s {
	bundle *src;
	bundle *dst;
};

static struct debug_info_s __info;

static struct debugger_info_s *__create_debugger_info(void)
{
	struct debugger_info_s *info;

	info = calloc(1, sizeof(struct debugger_info_s));
	if (info == NULL) {
		_E("out of memory");
		return NULL;
	}

	return info;
}

static void __destroy_debugger_info(gpointer data)
{
	struct debugger_info_s *info = (struct debugger_info_s *)data;

	if (info == NULL)
		return;

	if (info->default_opt_list)
		g_list_free_full(info->default_opt_list, free);
	if (info->last_extra_key_list)
		g_list_free_full(info->last_extra_key_list, free);
	if (info->attach)
		free(info->attach);
	if (info->unlink_list)
		g_list_free_full(info->unlink_list, free);
	if (info->extra_env_list)
		g_list_free_full(info->extra_env_list, free);
	if (info->extra_key_list)
		g_list_free_full(info->extra_key_list, free);
	if (info->name)
		free(info->name);
	free(info);
}

static struct debugger_info_s *__find_debugger_info(const char *name)
{
	struct debugger_info_s *debugger;
	GList *iter;

	iter = __info.debugger_list;
	while (iter) {
		debugger = (struct debugger_info_s *)iter->data;
		if (debugger && debugger->name &&
				!strcmp(debugger->name, name))
			return debugger;

		iter = g_list_next(iter);
	}

	return NULL;
}

static GList *__parse_file(GList *list, const char *path)
{
	FILE *fp;
	char buf[LINE_MAX];
	char *tok1 = NULL;
	char *tok2 = NULL;
	struct debugger_info_s *info = NULL;

	fp = fopen(path, "rt");
	if (fp == NULL)
		return list;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		FREE_AND_NULL(tok1);
		FREE_AND_NULL(tok2);
		sscanf(buf, "%ms %ms", &tok1, &tok2);
		if (tok1 && strcasecmp(TAG_DEBUGGER, tok1) == 0) {
			if (info) {
				_D("name: %s", info->name);
				list = g_list_append(list, info);
			}

			info = __create_debugger_info();
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
				_E("out of memory");
				__destroy_debugger_info(info);
				info = NULL;
				break;
			}
		} else if (strcasecmp(TAG_EXTRA_KEY, tok1) == 0) {
			info->extra_key_list = g_list_append(
					info->extra_key_list, strdup(tok2));
		} else if (strcasecmp(TAG_EXTRA_ENV, tok1) == 0) {
			info->extra_env_list = g_list_append(
					info->extra_env_list, strdup(tok2));
		} else if (strcasecmp(TAG_UNLINK, tok1) == 0) {
			info->unlink_list = g_list_append(info->unlink_list,
					strdup(tok2));
		} else if (strcasecmp(TAG_ATTACH, tok1) == 0) {
			info->attach = strdup(tok2);
			if (info->attach == NULL) {
				_E("attach is NULL");
				__destroy_debugger_info(info);
				info = NULL;
				break;
			}
		} else if (strcasecmp(TAG_LAST_EXTRA_KEY, tok1) == 0) {
			info->last_extra_key_list = g_list_append(
					info->last_extra_key_list,
					strdup(tok2));
		} else if (strcasecmp(TAG_DEFAULT_OPT, tok1) == 0) {
			info->default_opt_list = g_list_append(
					info->default_opt_list,
					strdup(tok2));
		}
	}
	fclose(fp);

	if (info) {
		_D("name: %s", info->name);
		list = g_list_append(list, info);
	}

	if (tok1)
		free(tok1);
	if (tok2)
		free(tok2);

	return list;
}

static int __load_debugger_info(const char *path)
{
	DIR *dp;
	struct dirent *dentry = NULL;
	char buf[PATH_MAX];
	char *ext;

	if (path == NULL)
		return -1;

	dp = opendir(path);
	if (dp == NULL)
		return -1;

	while ((dentry = readdir(dp)) != NULL) {
		if (dentry->d_name[0] == '.')
			continue;

		ext = strrchr(dentry->d_name, '.');
		if (ext && strcmp(ext, ".debugger") == 0) {
			snprintf(buf, sizeof(buf), "%s/%s",
					path, dentry->d_name);
			__info.debugger_list = __parse_file(
					__info.debugger_list, buf);
		}
	}
	closedir(dp);

	return 0;
}

static void __unload_debugger_info(void)
{
	if (__info.debugger_list == NULL)
		return;

	g_list_free_full(__info.debugger_list, __destroy_debugger_info);
	__info.debugger_list = NULL;
}

API int aul_debug_info_init(void)
{
	int r;

	if (__info.initialized)
		return AUL_R_OK;

	r = __load_debugger_info(PATH_AUL);
	if (r != 0) {
		_E("Failed to loader debugger information");
		return AUL_R_ERROR;
	}

	__info.initialized = true;
	return AUL_R_OK;
}

API int aul_debug_info_fini(void)
{
	if (!__info.initialized)
		return AUL_R_OK;

	__unload_debugger_info();

	__info.initialized = false;
	return AUL_R_OK;
}

static void __copy_data(bundle *src, bundle *dst, const char *key)
{
	const char **str_arr;
	char *str = NULL;
	int len = 0;

	if (bundle_get_type(src, key) == BUNDLE_TYPE_STR_ARRAY) {
		str_arr = bundle_get_str_array(src, key, &len);
		if (str_arr) {
			bundle_del(dst, key);
			bundle_add_str_array(dst, key, str_arr, len);
		}
	} else {
		bundle_get_str(src, key, &str);
		if (str) {
			bundle_del(dst, key);
			bundle_add_str(dst, key, str);
		}
	}
}

static void __foreach_cb(gpointer data, gpointer user_data)
{
	struct cb_data_s *cb_data = (struct cb_data_s *)user_data;
	const char *key = (const char *)data;

	if (!key || !cb_data) {
		_E("Critical error!");
		return;
	}

	__copy_data(cb_data->src, cb_data->dst, key);
	_D("[__DEBUG_INFO__] key(%s)", key);
}

static void __set_debug_info(struct debugger_info_s *debugger,
		bundle *src, bundle *dst)
{
	const char *val;
	struct cb_data_s cb_data = {
		.src = src,
		.dst = dst
	};

	__copy_data(src, dst, AUL_K_SDK);
	if (debugger->extra_key_list)
		g_list_foreach(debugger->extra_key_list, __foreach_cb, &cb_data);
	if (debugger->extra_env_list)
		g_list_foreach(debugger->extra_env_list, __foreach_cb, &cb_data);
	if (debugger->unlink_list)
		g_list_foreach(debugger->unlink_list, __foreach_cb, &cb_data);
	if (debugger->last_extra_key_list)
		g_list_foreach(debugger->last_extra_key_list, __foreach_cb, &cb_data);
	if (debugger->default_opt_list)
		g_list_foreach(debugger->default_opt_list, __foreach_cb, &cb_data);

	val = bundle_get_val(src, AUL_K_ORG_CALLER_PID);
	if (!val)
		val = bundle_get_val(src, AUL_K_CALLER_PID);

	if (val) {
		bundle_del(dst, AUL_K_ORG_CALLER_PID);
		bundle_add(dst, AUL_K_ORG_CALLER_PID, val);
	}

	_D("[__DEBUG_INFO__] Debugger(%s)", debugger->name);
}

API int aul_debug_info_set(bundle *src, bundle *dst)
{
	const char *name;
	struct debugger_info_s *debugger;

	if (!src || !dst) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	if (!__info.initialized) {
		_E("Debug info is not initilaized");
		return AUL_R_ERROR;
	}

	name = bundle_get_val(src, AUL_K_SDK);
	if (!name) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	debugger = __find_debugger_info(name);
	if (!debugger) {
		_E("Failed to find debugger(%s)", name);
		return AUL_R_EINVAL;
	}

	__set_debug_info(debugger, src, dst);

	return AUL_R_OK;
}
