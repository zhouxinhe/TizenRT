/*
 * Copyright (c) 2016 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <ctype.h>
#include <gio/gio.h>
#include <aul_svc.h>
#include <pkgmgr-info.h>
#include <aul_sock.h>
#include <aul.h>
#include <bundle.h>
#include <bundle_internal.h>

#include "amd_util.h"
#include "amd_app_property.h"
#include "amd_request.h"
#include "amd_appinfo.h"
#include "amd_cynara.h"

struct metadata_filter {
	char *key;
	char *value; /* Could be NULL */
};

struct metadata_entity {
	char *appid;
	char *key;
	char *value;
};

struct app_property_s {
	uid_t uid;
	GHashTable *alias_info_table;
	GHashTable *allowed_info_table;
	GHashTable *appid_cache_table;
	GList *metadata_list;
};

static GHashTable *user_prop_table;
static GList *metadata_filters;

static int __foreach_allowed_info(const char *appid, const char *allowed_appid,
		void *data);
static int __foreach_metadata_info(const pkgmgrinfo_appinfo_h handle,
		void *data);
static void __free_metadata_entity(gpointer data);

static int __add_alias_info(const char *alias_appid,
		const char *appid, void *user_data)
{
	GHashTable *alias_info_table = (GHashTable *)user_data;
	char *key;
	char *value;
	char *id;

	if (alias_appid == NULL || appid == NULL || alias_info_table == NULL) {
		_W("Invalid parameter");
		return -1;
	}

	key = strdup(alias_appid);
	if (key == NULL) {
		_E("out of memory");
		return -1;
	}

	value = strdup(appid);
	if (value == NULL) {
		_E("out of memory");
		free(key);
		return -1;
	}

	id = g_hash_table_lookup(alias_info_table, key);
	if (id) {
		_D("Replace alias info - alias_appid(%s), appid(%s)",
				key, value);
		g_hash_table_replace(alias_info_table, key, value);
	} else {
		g_hash_table_insert(alias_info_table, key, value);
	}

	return 0;
}

int _app_property_add_alias_info(app_property_h app_property,
		const char *alias_appid, const char *appid)
{
	int ret;

	if (app_property == NULL || appid == NULL) {
		_W("Invalid parameter");
		return -1;
	}

	if (alias_appid && appid) {
		ret = __add_alias_info(alias_appid, appid,
				app_property->alias_info_table);
		if (ret < 0) {
			_W("Failed to add alias info");
			return -1;
		}
	} else if (appid) {
		ret = aul_svc_foreach_alias_info_by_appid_for_uid(
				__add_alias_info, appid,
				app_property->uid,
				app_property->alias_info_table);
		if (ret < 0) {
			_W("Failed to retrive alias info - appid(%s)", appid);
			return -1;
		}
	}

	return 0;
}

static gboolean __remove_alias_info(gpointer key, gpointer value,
		gpointer user_data)
{
	if (value == NULL || user_data == NULL) {
		_W("Invalid parameter");
		return FALSE;
	}

	if (strcmp(value, user_data) == 0)
		return TRUE;

	return FALSE;
}

int _app_property_remove_alias_info(app_property_h app_property,
		const char *alias_appid, const char *appid)
{
	const char *id;

	if (app_property == NULL || (alias_appid == NULL && appid == NULL)) {
		_W("Invalid parameter");
		return -1;
	}

	if (alias_appid) {
		id = g_hash_table_lookup(app_property->alias_info_table,
				alias_appid);
		if (id) {
			g_hash_table_remove(app_property->alias_info_table,
					alias_appid);
		}
	} else {
		g_hash_table_foreach_remove(app_property->alias_info_table,
				__remove_alias_info, (gpointer)appid);
	}

	return 0;
}

const char *_app_property_get_real_appid(app_property_h app_property,
		const char *alias_appid)
{
	if (app_property == NULL || alias_appid == NULL) {
		_W("Invalid parameter");
		return NULL;
	}

	return g_hash_table_lookup(app_property->alias_info_table, alias_appid);
}

GList *_app_property_get_allowed_app_list(app_property_h app_property,
		const char *appid)
{
	if (app_property == NULL || appid == NULL) {
		_W("Invalid parameter");
		return NULL;
	}

	return g_hash_table_lookup(app_property->allowed_info_table, appid);
}

app_property_h _app_property_find(uid_t uid)
{
	if (user_prop_table == NULL)
		return NULL;

	return g_hash_table_lookup(user_prop_table, GUINT_TO_POINTER(uid));
}

int _app_property_insert(uid_t uid, const char *appid,
		const pkgmgrinfo_appinfo_h handle)
{
	int ret;
	app_property_h app_property;

	if (appid == NULL || handle == NULL) {
		_W("Invalid parameter");
		return -1;
	}

	app_property = _app_property_find(uid);
	if (app_property == NULL)
		return -1;

	g_hash_table_remove_all(app_property->appid_cache_table);

	ret = aul_svc_foreach_alias_info_by_appid_for_uid(__add_alias_info,
			appid, app_property->uid,
			app_property->alias_info_table);
	if (ret < 0) {
		_E("Failed to retrieve alias info - %s:%u:%d",
				appid, uid, ret);
		return -1;
	}

	ret = aul_svc_foreach_allowed_info_by_appid_for_uid(
			__foreach_allowed_info, appid,
			app_property->uid, app_property->allowed_info_table);
	if (ret < 0) {
		_E("Failed to retrieve allowed info - %s:%u:%d",
				appid, uid, ret);
		return -1;
	}

	ret = __foreach_metadata_info(handle, app_property);
	if (ret < 0) {
		_E("Failed to retrieve metadata info - %s:%u:%d",
				appid, uid, ret);
		return -1;
	}

	_D("uid(%d), appid(%s)", uid, appid);

	return 0;
}

int _app_property_delete(uid_t uid, const char *appid)
{
	app_property_h app_property;
	struct metadata_entity *entity;
	GList *iter;

	if (appid == NULL) {
		_W("Invalid parameter");
		return -1;
	}

	app_property = _app_property_find(uid);
	if (app_property == NULL)
		return -1;

	iter = app_property->metadata_list;
	while (iter) {
		entity = (struct metadata_entity *)iter->data;
		iter = g_list_next(iter);
		if (strcmp(entity->appid, appid) == 0) {
			app_property->metadata_list = g_list_remove(
					app_property->metadata_list,
					entity);
			__free_metadata_entity(entity);
		}
	}

	g_hash_table_remove_all(app_property->appid_cache_table);

	g_hash_table_foreach_remove(app_property->alias_info_table,
			__remove_alias_info, (gpointer)appid);

	g_hash_table_remove(app_property->allowed_info_table, appid);
	_D("uid(%d), appid(%s)", uid, appid);

	return 0;
}

static void __foreach_alias_info(const char *alias_appid, const char *appid,
		void *data)
{
	GHashTable *alias_info_table = (GHashTable *)data;
	char *key;
	char *value;

	if (alias_appid == NULL || appid == NULL || alias_info_table == NULL) {
		_W("Invalid parameter");
		return;
	}

	key = strdup(alias_appid);
	if (key == NULL) {
		_E("out of memory");
		return;
	}

	value = strdup(appid);
	if (value == NULL) {
		_E("out of memory");
		free(key);
		return;
	}

	g_hash_table_insert(alias_info_table, key, value);
}

static int __foreach_allowed_info(const char *appid, const char *allowed_appid,
		void *data)
{
	GHashTable *allowed_info_table = (GHashTable *)data;
	char *key;
	char *value;
	GList *list;

	if (appid == NULL || allowed_appid == NULL ||
			allowed_info_table == NULL) {
		_W("Invalid parameter");
		return -1;
	}

	value = strdup(allowed_appid);
	if (value == NULL) {
		_E("out of memory");
		return -1;
	}

	list = g_hash_table_lookup(allowed_info_table, appid);
	if (list) {
		list = g_list_append(list, value);
	} else {
		key = strdup(appid);
		if (key == NULL) {
			_E("out of memory");
			free(value);
			return -1;
		}

		list = g_list_append(list, value);
		g_hash_table_insert(allowed_info_table, key, list);
	}

	return 0;
}

static void __destroy_allowed_info_list(gpointer data)
{
	GList *list = (GList *)data;

	if (list == NULL)
		return;

	g_list_free_full(list, free);
}

static struct app_property_s *__create_app_property(uid_t uid)
{
	struct app_property_s *prop;

	prop = calloc(1, sizeof(struct app_property_s));
	if (prop == NULL) {
		_E("out of memory");
		return NULL;
	}

	prop->uid = uid;
	prop->alias_info_table = g_hash_table_new_full(g_str_hash, g_str_equal,
			free, free);
	if (prop->alias_info_table == NULL) {
		_E("Failed to create alias info table");
		free(prop);
		return NULL;
	}

	prop->allowed_info_table = g_hash_table_new_full(g_str_hash,
			g_str_equal, free, __destroy_allowed_info_list);
	if (prop->allowed_info_table == NULL) {
		_E("Failed to create allowed info table");
		g_hash_table_destroy(prop->alias_info_table);
		free(prop);
		return NULL;
	}

	prop->appid_cache_table = g_hash_table_new_full(g_str_hash, g_str_equal,
			free, free);
	if (prop->appid_cache_table == NULL) {
		_E("Failed to create appid cache table");
		g_hash_table_destroy(prop->allowed_info_table);
		g_hash_table_destroy(prop->alias_info_table);
		free(prop);
		return NULL;
	}

	prop->metadata_list = NULL;

	return prop;
}

static void __free_metadata_entity(gpointer data)
{
	struct metadata_entity *entity = data;

	if (!entity)
		return;

	if (entity->appid)
		free(entity->appid);
	if (entity->key)
		free(entity->key);
	if (entity->value)
		free(entity->value);
	free(entity);
}

static void __destroy_app_property(gpointer data)
{
	struct app_property_s *prop = (struct app_property_s *)data;

	if (prop == NULL)
		return;

	if (prop->allowed_info_table)
		g_hash_table_destroy(prop->allowed_info_table);
	if (prop->alias_info_table)
		g_hash_table_destroy(prop->alias_info_table);
	if (prop->appid_cache_table)
		g_hash_table_destroy(prop->appid_cache_table);
	if (prop->metadata_list)
		g_list_free_full(prop->metadata_list, __free_metadata_entity);

	free(prop);
}

static gint __comp_metadata_list(gconstpointer a, gconstpointer b)
{
	const struct metadata_entity *entity1 = a;
	const struct metadata_entity *entity2 = b;

	if (!a || !b)
		return -1;

	if (!strcmp(entity1->appid, entity2->appid) &&
			!strcmp(entity1->key, entity2->key) &&
			!strcmp(entity1->value, entity2->value))
		return 0;

	return -1;
}

static void __add_metadata_info(const char *appid, const char *key,
		const char *val, struct app_property_s *prop)
{
	struct metadata_entity *entity;
	GList *found;

	if (appid == NULL || key == NULL || val == NULL) {
		_W("Invalid parameter");
		return;
	}

	entity = calloc(1, sizeof(struct metadata_entity));
	if (entity == NULL) {
		_E("out of memory");
		return;
	}

	entity->appid = strdup(appid);
	if (!entity->appid) {
		_E("out of memory");
		__free_metadata_entity(entity);
		return;
	}

	entity->key = strdup(key);
	if (!entity->key) {
		_E("out of memory");
		__free_metadata_entity(entity);
		return;
	}

	entity->value = strdup(val);
	if (!entity->value) {
		_E("out of memory");
		__free_metadata_entity(entity);
		return;
	}

	found = g_list_find_custom(prop->metadata_list, entity,
			__comp_metadata_list);
	if (found) {
		__free_metadata_entity(entity);
		return;
	}

	prop->metadata_list = g_list_append(prop->metadata_list, entity);
}

static int __foreach_metadata_info(const pkgmgrinfo_appinfo_h handle,
		void *user_data)
{
	struct app_property_s *prop = user_data;
	char *appid = NULL;
	char *val;
	int ret;
	GList *iter;
	struct metadata_filter *filter;

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret < 0 || !appid)
		return -1;

	for (iter = metadata_filters; iter; iter = g_list_next(iter)) {
		filter = (struct metadata_filter *)iter->data;
		val = NULL;
		ret = pkgmgrinfo_appinfo_get_metadata_value(handle,
				filter->key, &val);
		if (ret == PMINFO_R_OK)
			__add_metadata_info(appid, filter->key, val, prop);
	}

	return 0;
}

static int __load_metadata(struct app_property_s *prop)
{
	pkgmgrinfo_appinfo_metadata_filter_h handle;
	int ret;
	GList *iter;
	struct metadata_filter *filter;

	ret = pkgmgrinfo_appinfo_metadata_filter_create(&handle);
	if (ret != PMINFO_R_OK)
		return -1;

	for (iter = metadata_filters; iter; iter = g_list_next(iter)) {
		filter = (struct metadata_filter *)iter->data;
		ret = pkgmgrinfo_appinfo_metadata_filter_add(handle,
				filter->key, filter->value);
		if (ret != PMINFO_R_OK) {
			pkgmgrinfo_appinfo_metadata_filter_destroy(handle);
			return -1;
		}
	}

	ret = pkgmgrinfo_appinfo_usr_metadata_filter_foreach(handle,
			__foreach_metadata_info, prop, prop->uid);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_metadata_filter_destroy(handle);
		return -1;
	}

	ret = pkgmgrinfo_appinfo_usr_metadata_filter_foreach(handle,
			__foreach_metadata_info, prop, GLOBAL_USER);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_metadata_filter_destroy(handle);
		return -1;
	}

	pkgmgrinfo_appinfo_metadata_filter_destroy(handle);

	return 0;
}

static int __load_app_property(struct app_property_s *prop)
{
	int ret;

	if (prop == NULL) {
		_W("Invalid parameter");
		return -1;
	}

	ret = aul_svc_foreach_alias_info_for_uid(__foreach_alias_info,
			prop->uid, prop->alias_info_table);
	if (ret < 0) {
		_E("Failed to retrieve alias info uid(%d) - ret(%d)",
				prop->uid, ret);
		return -1;
	}

	ret = aul_svc_foreach_allowed_info_for_uid(__foreach_allowed_info,
			prop->uid, prop->allowed_info_table);
	if (ret < 0) {
		_E("Failed to retrieve allowed info uid(%d) - ret(%d)",
				prop->uid, ret);
		return -1;
	}

	ret = __load_metadata(prop);
	if (ret < 0) {
		_E("Failed to retrieve metadata info uid(%d) - ret(%d)",
				prop->uid, ret);
		return -1;
	}

	return 0;
}

int _app_property_load(uid_t uid)
{
	int ret;
	struct app_property_s *prop;

	prop = __create_app_property(uid);
	if (prop == NULL)
		return -1;

	ret = __load_app_property(prop);
	if (ret < 0) {
		_E("Failed to load properties - ret(%d)", ret);
		__destroy_app_property(prop);
		return -1;
	}

	g_hash_table_insert(user_prop_table, GUINT_TO_POINTER(uid), prop);

	return 0;
}

void _app_property_unload(uid_t uid)
{
	g_hash_table_remove(user_prop_table, GUINT_TO_POINTER(uid));
}

static void __app_property_cache_put(app_property_h app_property,
		const char *checksum, const char *appid)
{
	if (!app_property || !checksum || !appid)
		return;

	g_hash_table_replace(app_property->appid_cache_table, strdup(checksum),
			strdup(appid));
}

static const char *__app_property_cache_get(app_property_h app_property,
		const char *checksum)
{
	if (!app_property || !checksum)
		return NULL;

	return g_hash_table_lookup(app_property->appid_cache_table, checksum);
}

void _app_property_cache_invalidate(app_property_h app_property)
{
	if (!app_property)
		return;

	g_hash_table_remove_all(app_property->appid_cache_table);
}

bool _app_property_metadata_query_bool(app_property_h app_property,
		const char *appid, const char *key)
{
	return _app_property_metadata_match(app_property, appid, key, "true");
}

int _app_property_metadata_foreach(app_property_h app_property,
		const char *appid, const char *key,
		int (*callback)(const char *value, void *data),
		void *user_data)
{
	struct metadata_entity *ret;
	GList *i;

	if (!app_property || !appid || !key)
		return -1;

	i = app_property->metadata_list;
	while (i) {
		ret = i->data;

		if (!strcmp(ret->appid, appid) &&
			!strcmp(ret->key, key)) {
			if (callback(ret->value, user_data) < 0)
				break;
		}

		i = g_list_next(i);
	}

	return 0;
}

bool _app_property_metadata_match(app_property_h app_property,
		const char *appid, const char *key, const char *value)
{
	struct metadata_entity entity;
	GList *i;

	if (!app_property || !appid || !key || !value)
		return false;

	entity.appid = (char *)appid;
	entity.key = (char *)key;
	entity.value = (char *)value;
	i = g_list_find_custom(app_property->metadata_list,
			&entity, __comp_metadata_list);
	if (!i)
		return false;

	return true;
}

static gint __comp_key(gconstpointer a, gconstpointer b)
{
	const struct metadata_entity *entity1 = a;
	const struct metadata_entity *entity2 = b;

	if (!a || !b)
		return -1;

	if (!strcmp(entity1->appid, entity2->appid) &&
			!strcmp(entity1->key, entity2->key)) {
		if (entity1->value && !strcmp(entity1->value, "false"))
			return -1;

		return 0;
	}

	return -1;
}

bool _app_property_metadata_query_activation(app_property_h app_property,
		const char *appid, const char *key)
{
	struct metadata_entity entity;
	GList *i;

	if (!app_property || !appid || !key)
		return false;

	entity.appid = (char *)appid;
	entity.key = (char *)key;
	entity.value = NULL;

	i = g_list_find_custom(app_property->metadata_list,
			&entity, __comp_key);
	if (!i)
		return false;

	return true;
}

static struct metadata_filter *__create_metadata_filter(const char *key,
		const char *value)
{
	struct metadata_filter *filter;

	filter = calloc(1, sizeof(struct metadata_filter));
	if (!filter) {
		_E("Out of memory");
		return NULL;
	}

	filter->key = strdup(key);
	if (!filter->key) {
		_E("Failed to duplicate key");
		free(filter);
		return NULL;
	}

	if (value) {
		filter->value = strdup(value);
		if (!filter->value) {
			_E("Failed to duplicate value");
			free(filter->key);
			free(filter);
			return NULL;
		}
	}

	return filter;
}

static void __destroy_metadata_filter(gpointer data)
{
	struct metadata_filter *filter = (struct metadata_filter *)data;

	if (!filter)
		return;

	if (filter->value)
		free(filter->value);
	if (filter->key)
		free(filter->key);
	free(filter);
}

static struct metadata_filter *__find_metadata_filter(const char *key,
		const char *value)
{
	struct metadata_filter *filter;
	GList *iter;

	iter = metadata_filters;
	while (iter) {
		filter = (struct metadata_filter *)iter->data;
		if (!strcmp(filter->key, key)) {
			if (value && filter->value &&
					!strcmp(filter->value, value))
				return filter;
			else if (!value && !filter->value)
				return filter;
		}
		iter = g_list_next(iter);
	}

	return NULL;
}

int _app_property_metadata_add_filter(const char *key, const char *value)
{
	struct metadata_filter *filter;

	if (!key) {
		_E("Invalid parameter");
		return -1;
	}

	filter = __find_metadata_filter(key, value);
	if (filter) {
		_W("Already exists");
		return -1;
	}

	filter = __create_metadata_filter(key, value);
	if (!filter)
		return -1;

	metadata_filters = g_list_append(metadata_filters, filter);

	return 0;
}

int _app_property_metadata_remove_filter(const char *key, const char *value)
{
	struct metadata_filter *filter;

	if (!key) {
		_E("Invalid parameter");
		return -1;
	}

	filter = __find_metadata_filter(key, value);
	if (!filter) {
		_E("Failed to find metadata filter(%s:%s)", key, value);
		return -1;
	}

	metadata_filters = g_list_remove(metadata_filters, filter);
	__destroy_metadata_filter(filter);

	return 0;
}

static int __dispatch_app_set_alias_appid(request_h req)
{
	int ret;
	const char *appid;
	const char *alias_appid;
	const struct appinfo *ai;
	bundle *kb;
	uid_t uid = _request_get_target_uid(req);
	app_property_h app_property;

	kb = _request_get_bundle(req);
	if (kb == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	alias_appid = bundle_get_val(kb, AUL_K_ALIAS_APPID);
	if (alias_appid == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	appid = bundle_get_val(kb, AUL_K_APPID);
	if (appid == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	ai = _appinfo_find(uid, appid);
	if (ai == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	ret = aul_svc_set_alias_appid_for_uid(alias_appid, appid, uid);
	if (ret < 0) {
		_E("Failed to set alias appid - alias_appid(%s), appid(%s)",
				alias_appid, appid);
		_request_send_result(req, ret);
		return -1;
	}

	app_property = _app_property_find(uid);
	if (app_property == NULL) {
		_E("Failed to find app property - uid(%d)", uid);
		_request_send_result(req, -1);
		return -1;
	}

	ret = _app_property_add_alias_info(app_property, alias_appid, appid);
	if (ret < 0) {
		_E("Failed to add alias info - %s:%s", alias_appid, appid);
		_request_send_result(req, ret);
		return -1;
	}

	_request_send_result(req, 0);

	return 0;
}

static int __dispatch_app_unset_alias_appid(request_h req)
{
	int ret;
	const char *alias_appid;
	bundle *kb;
	uid_t uid = _request_get_target_uid(req);
	app_property_h app_property;

	kb = _request_get_bundle(req);
	if (kb == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	alias_appid = bundle_get_val(kb, AUL_K_ALIAS_APPID);
	if (alias_appid == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	ret = aul_svc_unset_alias_appid_for_uid(alias_appid, uid);
	if (ret < 0) {
		_E("Failed to unset alias appid - alias_appid(%s)",
				alias_appid);
		_request_send_result(req, ret);
		return -1;
	}

	app_property = _app_property_find(uid);
	if (app_property == NULL) {
		_E("Failed to find app property - uid(%d)", uid);
		_request_send_result(req, -1);
		return -1;
	}

	ret = _app_property_remove_alias_info(app_property, alias_appid, NULL);
	if (ret < 0) {
		_E("Failed to remove alias info - %s", alias_appid);
		_request_send_result(req, ret);
		return -1;
	}

	_request_send_result(req, 0);

	return 0;
}

static int __dispatch_app_enable_alias_info(request_h req)
{
	int ret;
	const char *appid;
	bundle *kb;
	uid_t uid = _request_get_target_uid(req);
	app_property_h app_property;

	kb = _request_get_bundle(req);
	if (kb == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	appid = bundle_get_val(kb, AUL_K_APPID);
	if (appid == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	ret = aul_svc_enable_alias_info_for_uid(appid, uid);
	if (ret < 0) {
		_E("Failed to activate alias info - appid(%s)", appid);
		_request_send_result(req, ret);
		return -1;
	}

	app_property = _app_property_find(uid);
	if (app_property == NULL) {
		_E("Failed to find app property - uid(%d)", uid);
		_request_send_result(req, -1);
		return -1;
	}

	ret = _app_property_add_alias_info(app_property, NULL, appid);
	if (ret < 0) {
		_E("Failed to add alias info - %s", appid);
		_request_send_result(req, ret);
		return -1;
	}

	_request_send_result(req, 0);

	return 0;
}

static int __dispatch_app_disable_alias_info(request_h req)
{
	int ret;
	const char *appid;
	bundle *kb;
	uid_t uid = _request_get_target_uid(req);
	app_property_h app_property;

	kb = _request_get_bundle(req);
	if (kb == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	appid = bundle_get_val(kb, AUL_K_APPID);
	if (appid == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	ret = aul_svc_disable_alias_info_for_uid(appid, uid);
	if (ret < 0) {
		_E("Failed to deactivate alias info - appid(%s)", appid);
		_request_send_result(req, ret);
		return -1;
	}

	app_property = _app_property_find(uid);
	if (app_property == NULL) {
		_E("Failed to find app property - uid(%d)", uid);
		_request_send_result(req, -1);
	}

	ret = _app_property_remove_alias_info(app_property, NULL, appid);
	if (ret < 0) {
		_E("Failed to remove alias info - appid(%s)", appid);
		_request_send_result(req, ret);
		return -1;
	}

	_request_send_result(req, 0);

	return 0;
}

static int __dispatch_app_set_app_control_default_app(request_h req)
{
	bundle *kb = NULL;
	const char *op;
	const char *mime_type;
	const char *uri;
	const char *appid;
	int ret;
	app_property_h prop;

	kb = _request_get_bundle(req);
	if (kb == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	op = aul_svc_get_operation(kb);
	appid = aul_svc_get_appid(kb);
	if (op == NULL || appid == NULL) {
		_E("Invalid operation, appid");
		_request_send_result(req, -1);
		return -1;
	}

	mime_type = aul_svc_get_mime(kb);
	uri = aul_svc_get_uri(kb);

	ret = aul_svc_set_defapp_for_uid(op, mime_type, uri,
			appid, _request_get_target_uid(req));
	if (ret < 0) {
		_E("Error[%d], aul_svc_set_defapp", ret);
		_request_send_result(req, -1);
		return -1;
	}

	prop = _app_property_find(_request_get_target_uid(req));
	_app_property_cache_invalidate(prop);
	_request_send_result(req, 0);
	return 0;
}

static int __dispatch_app_unset_app_control_default_app(request_h req)
{
	char appid[MAX_PACKAGE_STR_SIZE];
	int ret;
	app_property_h prop;

	snprintf(appid, MAX_PACKAGE_STR_SIZE - 1, "%s",
			(const char *)_request_get_raw(req));

	ret = aul_svc_unset_defapp_for_uid(appid, _request_get_target_uid(req));
	if (ret < 0) {
		_E("Error[%d], aul_svc_unset_defapp", ret);
		_request_send_result(req, -1);
		return -1;
	}

	prop = _app_property_find(_request_get_target_uid(req));
	_app_property_cache_invalidate(prop);
	_request_send_result(req, 0);
	return 0;
}

static int __dispatch_app_get_appid_from_cache(request_h req)
{
	const char *checksum;
	const char *appid;
	bundle *b = _request_get_bundle(req);
	app_property_h prop = _app_property_find(_request_get_target_uid(req));

	checksum = bundle_get_val(b, AUL_K_CHECKSUM);
	appid  = __app_property_cache_get(prop, checksum);

	if (!appid) {
		aul_sock_send_raw_with_fd(_request_remove_fd(req),
				APP_GET_APPID_FROM_CACHE, NULL, 0,
				AUL_SOCK_NOREPLY);
		return 0;
	}

	aul_sock_send_raw_with_fd(_request_remove_fd(req),
		APP_GET_APPID_FROM_CACHE, (unsigned char *)appid,
		strlen(appid), AUL_SOCK_NOREPLY);

	return 0;
}

static int __dispatch_app_set_cache(request_h req)
{
	const char *appid;
	const char *checksum;
	bundle *b = _request_get_bundle(req);
	app_property_h prop = _app_property_find(_request_get_target_uid(req));

	appid = bundle_get_val(b, AUL_K_APPID);
	checksum = bundle_get_val(b, AUL_K_CHECKSUM);

	if (!appid || !checksum) {
		_request_send_result(req, -1);
		return -1;
	}

	__app_property_cache_put(prop, checksum, appid);
	_request_send_result(req, 0);
	return 0;
}

static int __dispatch_app_invalidate_cache(request_h req)
{
	app_property_h prop = _app_property_find(_request_get_target_uid(req));

	_app_property_cache_invalidate(prop);
	_request_send_result(req, 0);
	return 0;
}

static request_cmd_dispatch __dispatch_table[] = {
	{
		.cmd = APP_SET_ALIAS_APPID,
		.callback = __dispatch_app_set_alias_appid
	},
	{
		.cmd = APP_UNSET_ALIAS_APPID,
		.callback = __dispatch_app_unset_alias_appid
	},
	{
		.cmd = APP_ENABLE_ALIAS_INFO,
		.callback = __dispatch_app_enable_alias_info
	},
	{
		.cmd = APP_DISABLE_ALIAS_INFO,
		.callback = __dispatch_app_disable_alias_info
	},
	{
		.cmd = APP_SET_APP_CONTROL_DEFAULT_APP,
		.callback = __dispatch_app_set_app_control_default_app
	},
	{
		.cmd = APP_UNSET_APP_CONTROL_DEFAULT_APP,
		.callback = __dispatch_app_unset_app_control_default_app
	},
	{
		.cmd = APP_GET_APPID_FROM_CACHE,
		.callback = __dispatch_app_get_appid_from_cache
	},
	{
		.cmd = APP_SET_CACHE,
		.callback = __dispatch_app_set_cache
	},
	{
		.cmd = APP_INVALIDATE_CACHE,
		.callback = __dispatch_app_invalidate_cache
	},
};

static cynara_checker __cynara_checkers[] = {
	{
		.cmd = APP_SET_APP_CONTROL_DEFAULT_APP,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_SYSTEM_SETTING
	},
	{
		.cmd = APP_UNSET_APP_CONTROL_DEFAULT_APP,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_SYSTEM_SETTING
	},
	{
		.cmd = APP_SET_ALIAS_APPID,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_SYSTEM_SETTING
	},
	{
		.cmd = APP_UNSET_ALIAS_APPID,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_SYSTEM_SETTING
	},
	{
		.cmd = APP_ENABLE_ALIAS_INFO,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_SYSTEM_SETTING
	},
	{
		.cmd = APP_DISABLE_ALIAS_INFO,
		.checker = _cynara_simple_checker,
		.data = PRIVILEGE_SYSTEM_SETTING
	},
};

int _app_property_init(void)
{
	struct metadata_filter metadata_table[] = {
		{ METADATA_LARGEMEMORY, NULL },
		{ METADATA_OOMTERMINATION, NULL },
		{ METADATA_VIPAPP, NULL },
	};
	int r;
	int i;

	_D("app property init");

	user_prop_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
			NULL, __destroy_app_property);
	if (user_prop_table == NULL) {
		_E("Failed to create user prop table");
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(metadata_table); i++) {
		r = _app_property_metadata_add_filter(metadata_table[i].key,
				metadata_table[i].value);
		if (r != 0)
			return -1;
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

void _app_property_fini(void)
{
	_D("app property fini");

	if (metadata_filters)
		g_list_free_full(metadata_filters, __destroy_metadata_filter);

	if (user_prop_table)
		g_hash_table_destroy(user_prop_table);
}


