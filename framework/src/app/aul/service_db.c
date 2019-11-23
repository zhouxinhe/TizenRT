/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <glib.h>
#include <unistd.h>
#include <ctype.h>
#include <sqlite3.h>
#include <tzplatform_config.h>
#include <pkgmgr-info.h>

#include "aul_svc_db.h"
#include "aul_util.h"

#define APP_INFO_DB_PATH tzplatform_mkpath(TZ_SYS_DB, ".pkgmgr_parser.db")

#define QUERY_MAX_LEN   8192
#define URI_MAX_LEN 4096
#define BUF_MAX_LEN 1024
#define ROOT_UID	0

#define SVC_COLLATION "appsvc_collation"

#define QUERY_CREATE_TABLE_APPSVC "create table if not exists appsvc " \
	"(operation text, " \
	"mime_type text, " \
	"uri text, " \
	"pkg_name text, " \
	"PRIMARY KEY(pkg_name)) "

#define __BIND_TEXT(db, stmt, i, text)						\
do {										\
	if (sqlite3_bind_text(stmt, i, text, -1, SQLITE_STATIC) != SQLITE_OK) {	\
		_E("bind error(index %d): %s", i, sqlite3_errmsg(db));		\
		sqlite3_finalize(stmt);						\
		return -1;							\
	}									\
} while (0)

#define __BIND_INT(db, stmt, i, int)						\
do {										\
	if (sqlite3_bind_int(stmt, i, int) != SQLITE_OK) {			\
		_E("bind error(index %d): %s", i, sqlite3_errmsg(db));		\
		sqlite3_finalize(stmt);						\
		return -1;							\
	}									\
} while (0)

struct alias_info_s {
	char *alias_appid;
	char *appid;
};

struct allowed_info_s {
	uid_t uid;
	char *appid;
	char *allowed_appid;
};

static char *__get_svc_db(uid_t uid)
{
	char db_path[PATH_MAX];

	if (uid >= REGULAR_UID_MIN) {
		snprintf(db_path, sizeof(db_path), "%s/user/%d/.appsvc.db",
				tzplatform_getenv(TZ_SYS_DB), uid);
	} else {
		snprintf(db_path, sizeof(db_path), "%s/.appsvc.db",
				tzplatform_getenv(TZ_SYS_DB));
	}

	return strdup(db_path);
}

/**
 * db initialize
 */
static int __init(uid_t uid, bool readonly, sqlite3 **svc_db)
{
	int rc;
	char *db_path;

	if (*svc_db) {
		_D("Already initialized");
		return 0;
	}

	db_path = __get_svc_db(uid);
	if (db_path == NULL) {
		_E("Failed to get service db path - %d", uid);
		return -1;
	}

	rc = sqlite3_open_v2(db_path, svc_db,
			readonly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE,
			NULL);
	if (rc) {
		_E("Can't open database(%s): %d, %s, extended: %d",
				db_path, rc, sqlite3_errmsg(*svc_db),
				sqlite3_extended_errcode(*svc_db));
		free(db_path);
		if (*svc_db) {
			sqlite3_close(*svc_db);
			*svc_db = NULL;
		}
		return -1;
	}
	free(db_path);

	return 0;
}

static int __collate_appsvc(void *ucol, int str1_len, const void *str1,
				int str2_len, const void *str2)
{
	char *saveptr1 = NULL;
	char *saveptr2 = NULL;
	char *dup_str1;
	char *dup_str2;
	char *token;
	char *in_op;
	char *in_uri;
	char *in_mime;
	char *op;
	char *uri;
	char *mime;

	if (str1 == NULL || str2 == NULL)
		return -1;

	dup_str1 = strdup(str1);
	if (dup_str1 == NULL)
		return -1;

	dup_str2 = strdup(str2);
	if (dup_str2 == NULL) {
		free(dup_str1);
		return -1;
	}

	in_op = strtok_r(dup_str2, "|", &saveptr1);
	in_uri = strtok_r(NULL, "|", &saveptr1);
	in_mime = strtok_r(NULL, "|", &saveptr1);

	if (!(in_op && in_uri && in_mime)) {
		SECURE_LOGD("op(%s) uri(%s) mime(%s)", in_op, in_uri, in_mime);
		free(dup_str1);
		free(dup_str2);
		return -1;
	}

	token = strtok_r(dup_str1, ";", &saveptr1);

	if (token == NULL) {
		free(dup_str1);
		free(dup_str2);
		return -1;
	}

	do {
		op = strtok_r(token, "|", &saveptr2);
		uri = strtok_r(NULL, "|", &saveptr2);
		mime = strtok_r(NULL, "|", &saveptr2);

		if (!(op && uri && mime)) {
			SECURE_LOGD("op(%s) uri(%s) mime(%s)", op, uri, mime);
			continue;
		}

		if ((strcmp(op, in_op) == 0) && (strcmp(mime, in_mime) == 0)) {
			SECURE_LOGD("%s %s %s %s %s %s", op, in_op, mime, in_mime, uri, in_uri);
			if (g_pattern_match_simple(uri, in_uri)) {
				SECURE_LOGD("in_uri : %s | uri : %s", in_uri, uri);
				free(dup_str1);
				free(dup_str2);
				return 0;
			}
		}
	} while ((token = strtok_r(NULL, ";", &saveptr1)));

	free(dup_str1);
	free(dup_str2);

	return -1;
}

static int __init_app_info_db(uid_t uid, sqlite3 **app_info_db, sqlite3 **global_app_info_db)
{
	int rc;
	char *db_path;

	if (*app_info_db && *global_app_info_db) {
		_D("Already initialized");
		return 0;
	}

	db_path = getUserPkgParserDBPathUID(uid);
	if (db_path == NULL) {
		_E("Failed to get pkg parser db path - %d", uid);
		return -1;
	}

	rc = sqlite3_open_v2(db_path, app_info_db, SQLITE_OPEN_READONLY, NULL);
	free(db_path);
	if (rc) {
		_E("Can't open database: %d, %s, extended: %d",
				rc, sqlite3_errmsg(*app_info_db),
				sqlite3_extended_errcode(*app_info_db));
		goto err;
	}

	rc = sqlite3_exec(*app_info_db, "PRAGMA journal_mode = PERSIST",
					NULL, NULL, NULL);
	if (SQLITE_OK != rc) {
		_D("Fail to change journal mode");
		goto err;
	}

	sqlite3_create_collation(*app_info_db, SVC_COLLATION, SQLITE_UTF8,
			NULL, __collate_appsvc);

	rc = sqlite3_open_v2(APP_INFO_DB_PATH, global_app_info_db,
			SQLITE_OPEN_READONLY, NULL);
	if (rc) {
		_E("Can't open database: %d, %s, extended: %d",
				rc, sqlite3_errmsg(*global_app_info_db),
				sqlite3_extended_errcode(*global_app_info_db));
		goto err;
	}

	rc = sqlite3_exec(*global_app_info_db, "PRAGMA journal_mode = PERSIST",
			NULL, NULL, NULL);
	if (SQLITE_OK != rc) {
		_D("Fail to change journal mode");
		goto err;
	}

	sqlite3_create_collation(*global_app_info_db, SVC_COLLATION, SQLITE_UTF8,
			NULL, __collate_appsvc);

	return 0;
err:
	if (*app_info_db) {
		sqlite3_close(*app_info_db);
		*app_info_db = NULL;
	}

	if (*global_app_info_db) {
		sqlite3_close(*global_app_info_db);
		*global_app_info_db = NULL;
	}

	return -1;
}

static void __fini_app_info_db(sqlite3 **app_info_db, sqlite3 **global_app_info_db)
{
	if (*app_info_db) {
		sqlite3_close(*app_info_db);
		*app_info_db = NULL;
	}

	if (*global_app_info_db) {
		sqlite3_close(*global_app_info_db);
		*global_app_info_db = NULL;
	}
}

static int __fini(sqlite3 **svc_db)
{
	if (*svc_db) {
		sqlite3_close(*svc_db);
		*svc_db = NULL;
	}
	return 0;
}

int _svc_db_check_perm(uid_t uid, bool readonly)
{
	int ret = 0;
	char *db;
	sqlite3 *svc_db = NULL;

	if (__init(uid, readonly, &svc_db) < 0)
		return -1;

	db = __get_svc_db(uid);
	if (db == NULL) {
		__fini(&svc_db);
		return -1;
	}

	ret = access(db, readonly ? R_OK : (R_OK | W_OK));
	free(db);
	__fini(&svc_db);
	return ret;
}

static int __insert_info(sqlite3 *db, const char *op, const char *mime_type,
		const char *uri, const char *appid)
{
	const char query[] =
		"INSERT INTO appsvc(operation, mime_type, uri, pkg_name) "
		"VALUES(?, ?, ?, ?)";
	sqlite3_stmt *stmt;
	int idx = 1;
	int r;

	r = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (r != SQLITE_OK) {
		_E("Prepare failed: %s", sqlite3_errmsg(db));
		return -1;
	}

	__BIND_TEXT(db, stmt, idx++, op);
	__BIND_TEXT(db, stmt, idx++, mime_type ? mime_type : "NULL");
	__BIND_TEXT(db, stmt, idx++, uri ? uri : "NULL");
	__BIND_TEXT(db, stmt, idx++, appid);

	r = sqlite3_step(stmt);
	if (r != SQLITE_DONE) {
		_E("Step failed: %s", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return -1;
	}
	sqlite3_finalize(stmt);

	return 0;
}

int _svc_db_add_app(const char *op, const char *mime_type, const char *uri,
		const char *pkg_name, uid_t uid)
{
	int r;
	sqlite3 *svc_db = NULL;

	if (__init(uid, false, &svc_db) < 0)
		return -1;

	if (op == NULL)
		return -1;

	r = __insert_info(svc_db, op, mime_type, uri, pkg_name);
	__fini(&svc_db);

	return r;
}

static int __delete_info(sqlite3 *db, const char *appid)
{
	const char query[] = "DELETE FROM appsvc WHERE pkg_name = ?;";
	sqlite3_stmt *stmt;
	int idx = 1;
	int r;

	r = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (r != SQLITE_OK) {
		_E("Prepare failed: %s", sqlite3_errmsg(db));
		return -1;
	}

	__BIND_TEXT(db, stmt, idx++, appid);

	r = sqlite3_step(stmt);
	if (r != SQLITE_DONE) {
		_E("Step failed: %s", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return -1;
	}
	sqlite3_finalize(stmt);

	return 0;
}

int _svc_db_delete_with_pkgname(const char *pkg_name, uid_t uid)
{
	int r;
	sqlite3 *svc_db = NULL;

	if (pkg_name == NULL) {
		_E("Invalid argument: data to delete is NULL");
		return -1;
	}

	if (__init(uid, false, &svc_db) < 0)
		return -1;

	r = __delete_info(svc_db, pkg_name);
	__fini(&svc_db);

	return r;
}

int _svc_db_delete_all(uid_t uid)
{
	const char query[] = "DELETE FROM appsvc;";
	int r;
	sqlite3 *svc_db = NULL;

	if (__init(uid, false, &svc_db) < 0)
		return -1;

	r = sqlite3_exec(svc_db, query, NULL, NULL, NULL);
	if (r != SQLITE_OK) {
		_E("Exec failed: %s", sqlite3_errmsg(svc_db));
		__fini(&svc_db);
		return -1;
	}
	__fini(&svc_db);

	return 0;
}

static int __get_count(sqlite3 *db, const char *appid)
{
	const char query[] = "SELECT COUNT(*) FROM appsvc WHERE pkg_name = ?;";
	sqlite3_stmt *stmt;
	int idx = 1;
	int count;
	int r;

	r = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (r != SQLITE_OK) {
		_E("Prepare failed: %s", sqlite3_errmsg(db));
		return -1;
	}

	__BIND_TEXT(db, stmt, idx++, appid);

	r = sqlite3_step(stmt);
	if (r == SQLITE_ROW)
		count = sqlite3_column_int(stmt, 0);
	else
		count = 0;

	sqlite3_finalize(stmt);

	return count;
}

int _svc_db_is_defapp(const char *pkg_name, uid_t uid)
{
	int r;
	sqlite3 *svc_db = NULL;

	if (pkg_name == NULL) {
		_E("Invalid argument: data to delete is NULL");
		return 0;
	}

	if (__init(uid, true, &svc_db) < 0)
		return 0;

	r = __get_count(svc_db, pkg_name);
	__fini(&svc_db);

	if (r < 1)
		return 0;

	return 1;
}

static int __get_appid(sqlite3 *db, const char *op, const char *mime_type,
		const char *uri, char **appid)
{
	const char query[] =
		"SELECT pkg_name FROM appsvc WHERE operation = ? "
		"AND mime_type = ? AND uri = ?;";
	sqlite3_stmt *stmt;
	char *temp;
	int idx = 1;
	int r;

	r = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (r != SQLITE_OK) {
		_E("Prepare failed: %s", sqlite3_errmsg(db));
		return -1;
	}

	__BIND_TEXT(db, stmt, idx++, op);
	__BIND_TEXT(db, stmt, idx++, mime_type ? mime_type : "NULL");
	__BIND_TEXT(db, stmt, idx++, uri ? uri : "NULL");

	r = sqlite3_step(stmt);
	if (r != SQLITE_ROW) {
		_E("Step failed: %s", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return -1;
	}

	temp = (char *)sqlite3_column_text(stmt, 0);
	if (temp) {
		*appid = strdup(temp);
		if (*appid == NULL) {
			_E("Out of memory");
			sqlite3_finalize(stmt);
			return -1;
		}
	}

	sqlite3_finalize(stmt);

	return 0;
}

char *_svc_db_get_app(const char *op, const char *mime_type, const char *uri,
		uid_t uid)
{
	char *appid = NULL;
	int r;
	sqlite3 *svc_db = NULL;

	if (op == NULL)
		return NULL;

	if (__init(uid, true, &svc_db) < 0)
		return NULL;

	r = __get_appid(svc_db, op, mime_type, uri, &appid);
	if (r != 0) {
		__fini(&svc_db);
		return NULL;
	}
	__fini(&svc_db);
	SECURE_LOGD("appid: %s", appid);

	return appid;
}

static int __compare_appid(gconstpointer a, gconstpointer b)
{
	return strcmp(a, b);
}

static int __adjust_list_with_submode(sqlite3 *db, sqlite3 *app_info_db,
		int mainapp_mode, const char *win_id, GSList **list)
{
	const char query[] =
		"SELECT ac.app_id, ai.app_submode_mainid "
		"FROM package_app_app_control as ac, package_app_info ai "
		"WHERE ac.app_id = ai.app_id AND ai.app_submode_mainid != '';";
	sqlite3_stmt *stmt;
	char *sub_appid;
	char *submode_mainid;
	char *excluded_appid;
	GSList *found_subapp;
	GSList *found_mainapp;
	int r;

	r = sqlite3_prepare_v2(app_info_db, query, strlen(query), &stmt, NULL);
	if (r != SQLITE_OK) {
		_E("Prepare failed: %s", sqlite3_errmsg(app_info_db));
		return -1;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		sub_appid = (char *)sqlite3_column_text(stmt, 0);
		if (sub_appid == NULL)
			continue;

		found_subapp = g_slist_find_custom(*list, sub_appid,
				__compare_appid);
		if (found_subapp == NULL)
			continue;

		submode_mainid = (char *)sqlite3_column_text(stmt, 1);
		if (submode_mainid == NULL)
			continue;

		found_mainapp = g_slist_find_custom(*list, submode_mainid,
				__compare_appid);
		if (found_mainapp == NULL)
			continue;

		if (win_id && !mainapp_mode)
			excluded_appid = (char *)found_mainapp->data;
		else
			excluded_appid = (char *)found_subapp->data;

		if (excluded_appid) {
			_E("Remove %s from app list with submode",
					excluded_appid);
			*list = g_slist_remove(*list, excluded_appid);
			free(excluded_appid);
		}
	}
	sqlite3_finalize(stmt);

	return 0;
}

int _svc_db_adjust_list_with_submode(int mainapp_mode, char *win_id,
		GSList **pkg_list, uid_t uid)
{
	int r;
	sqlite3 *app_info_db = NULL;
	sqlite3 *global_app_info_db = NULL;

	if (__init_app_info_db(uid, &app_info_db, &global_app_info_db) < 0)
		return 0;

	r = __adjust_list_with_submode(app_info_db, app_info_db, mainapp_mode, win_id,
			pkg_list);
	if (r < 0) {
		__fini_app_info_db(&app_info_db, &global_app_info_db);
		return -1;
	}

	r = __adjust_list_with_submode(global_app_info_db, app_info_db, mainapp_mode, win_id,
			pkg_list);
	if (r < 0) {
		__fini_app_info_db(&app_info_db, &global_app_info_db);
		return -1;
	}
	__fini_app_info_db(&app_info_db, &global_app_info_db);

	return 0;
}

static int __get_list_with_query(sqlite3 *db, const char *query, GSList **list)
{
	sqlite3_stmt *stmt;
	GSList *found;
	char *str;
	char *appid;
	int r;

	r = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (r != SQLITE_OK) {
		_E("Prepare failed: %s", sqlite3_errmsg(db));
		return -1;
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		str = (char *)sqlite3_column_text(stmt, 0);
		if (str == NULL)
			continue;

		found = g_slist_find_custom(*list, str, __compare_appid);
		if (found == NULL) {
			appid = strdup(str);
			if (appid == NULL) {
				_E("Out of memory");
				break;
			}

			*list = g_slist_append(*list, appid);
			_D("%s is added", appid);
		}
	}
	sqlite3_finalize(stmt);

	return 0;
}

int _svc_db_get_list_with_all_defapps(GSList **pkg_list, uid_t uid)
{
	const char query[] = "SELECT pkg_name FROM appsvc;";
	int r;
	sqlite3 *svc_db = NULL;

	if (__init(uid, true, &svc_db) < 0)
		return -1;

	r = __get_list_with_query(svc_db, query, pkg_list);
	__fini(&svc_db);

	return r;
}

char *_svc_db_query_builder_add(char *old_query, char *op, char *uri,
		char *mime, bool collate)
{
	char *query;
	char *q;

	if (collate) {
		if (old_query) {
			query = sqlite3_mprintf("%s, '%q|%q|%q'",
					old_query, op, uri, mime);
			free(old_query);
		} else {
			query = sqlite3_mprintf("'%q|%q|%q'",
					op, uri, mime);
		}
	} else {
		if (old_query) {
			query = sqlite3_mprintf("%s OR ac.app_control like '%%%q|%q|%q%%' ",
					old_query, op, uri, mime);
			free(old_query);
		} else {
			query = sqlite3_mprintf("ac.app_control like '%%%q|%q|%q%%' ",
					op, uri, mime);
		}
	}

	q = strdup(query);
	sqlite3_free(query);
	return q;
}

char *_svc_db_query_builder_or(char *q1, char *q2)
{
	char query[QUERY_MAX_LEN];

	snprintf(query, sizeof(query), "(%s) or (%s)", q1, q2);
	free(q1);
	free(q2);

	return strdup(query);
}

char *_svc_db_query_builder_in(const char *field, char *args)
{
	char query[QUERY_MAX_LEN];

	snprintf(query, sizeof(query), "%s in(%s)", field, args);
	free(args);

	return strdup(query);
}

char *_svc_db_query_builder_build(char *old_query)
{
	char query[QUERY_MAX_LEN];

	if (old_query == NULL)
		return NULL;

	snprintf(query, sizeof(query),
			"SELECT ac.app_id FROM package_app_app_control "
			"as ac, package_app_info ai "
			"WHERE ac.app_id = ai.app_id "
			"AND ai.component_type='uiapp' AND (%s)",
			old_query);

	free(old_query);

	return strdup(query);
}

int _svc_db_exec_query(const char *query, GSList **pkg_list, uid_t uid)
{
	int r;
	sqlite3 *app_info_db = NULL;
	sqlite3 *global_app_info_db = NULL;

	if (query == NULL) {
		_E("query is NULL");
		return -1;
	}

	if (__init_app_info_db(uid, &app_info_db, &global_app_info_db) < 0)
		return 0;

	SECURE_LOGD("query : %s", query);

	r = __get_list_with_query(app_info_db, query, pkg_list);
	if (r < 0) {
		__fini_app_info_db(&app_info_db, &global_app_info_db);
		return -1;
	}

	r = __get_list_with_query(global_app_info_db, query, pkg_list);
	if (r < 0) {
		__fini_app_info_db(&app_info_db, &global_app_info_db);
		return -1;
	}
	__fini_app_info_db(&app_info_db, &global_app_info_db);

	return 0;
}

int _svc_db_add_alias_appid(const char *alias_appid, const char *appid,
		uid_t uid)
{
	int ret;
	sqlite3_stmt *stmt = NULL;
	sqlite3 *svc_db = NULL;
	const char *query =
		"INSERT OR REPLACE INTO alias_info(alias_appid, appid) " \
		"values(?,?);";
	int result = 0;

	if (alias_appid == NULL || appid == NULL) {
		_E("Invalid parameters");
		return -1;
	}

	if (__init(uid, false, &svc_db) < 0)
		return -1;

	ret = sqlite3_prepare_v2(svc_db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_E("sqlite3_prepare_v2() error: %d(%s)",
				ret, sqlite3_errmsg(svc_db));
		__fini(&svc_db);
		return ret;
	}

	ret = sqlite3_bind_text(stmt, 1, alias_appid, -1, SQLITE_TRANSIENT);
	if (ret != SQLITE_OK) {
		_E("sqlite3_bind_text() error: %d(%s)",
				ret, sqlite3_errmsg(svc_db));
		result = -1;
		goto end;
	}

	ret = sqlite3_bind_text(stmt, 2, appid, -1, SQLITE_TRANSIENT);
	if (ret != SQLITE_OK) {
		_E("sqlite3_bind_text() error: %d(%s)",
				ret, sqlite3_errmsg(svc_db));
		result = -1;
		goto end;
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		_E("sqlite3_step() error: %d(%s)",
				ret, sqlite3_errmsg(svc_db));
		result = -1;
		goto end;
	}

end:
	sqlite3_finalize(stmt);
	__fini(&svc_db);

	return result;
}

int _svc_db_delete_alias_appid(const char *alias_appid, uid_t uid)
{
	int ret;
	sqlite3_stmt *stmt = NULL;
	const char *query = "DELETE FROM alias_info WHERE alias_appid = ?;";
	int result = 0;
	sqlite3 *svc_db = NULL;

	if (alias_appid == NULL) {
		_E("Invalid parameter");
		return -1;
	}

	if (__init(uid, false, &svc_db) < 0)
		return -1;

	ret = sqlite3_prepare_v2(svc_db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_E("sqlite3_prepare_v2() error: %d(%s)",
				ret, sqlite3_errmsg(svc_db));
		__fini(&svc_db);
		return -1;
	}

	ret = sqlite3_bind_text(stmt, 1, alias_appid, -1, SQLITE_TRANSIENT);
	if (ret != SQLITE_OK) {
		_E("sqlite3_bind_text() error: %d(%s)",
				ret, sqlite3_errmsg(svc_db));
		result = -1;
		goto end;
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		_E("sqlite3_step() error: %d(%s)",
				ret, sqlite3_errmsg(svc_db));
		result = -1;
	}

end:
	sqlite3_finalize(stmt);
	__fini(&svc_db);

	return result;
}

int __get_appid_from_alias_info(const char *alias_appid, char **appid,
		uid_t uid, uid_t db_uid)
{
	int ret;
	int result = 0;
	sqlite3_stmt *stmt = NULL;
	const char *query;
	const char *real_appid;
	sqlite3 *svc_db = NULL;

	if (appid == NULL || alias_appid == NULL) {
		_E("Invalid parameter");
		return -1;
	}

	if (__init(db_uid, true, &svc_db) < 0)
		return -1;

	if (db_uid == GLOBAL_USER) {
		query = "SELECT appid FROM alias_info WHERE " \
			"alias_info.alias_appid = ? AND " \
			"alias_info.appid NOT IN " \
			"(SELECT appid FROM alias_info_for_uid WHERE " \
			"uid = ?);";
	} else {
		query = "SELECT appid FROM alias_info WHERE " \
			 "alias_appid = ? AND enable = 'true';";
	}

	ret = sqlite3_prepare_v2(svc_db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_E("sqlite3_prepare_v2() error: %d(%s)",
				ret, sqlite3_errmsg(svc_db));
		__fini(&svc_db);
		return -1;
	}

	ret = sqlite3_bind_text(stmt, 1, alias_appid, -1, SQLITE_TRANSIENT);
	if (ret != SQLITE_OK) {
		_E("sqlite3_bind_text() error: %d(%s)",
				ret, sqlite3_errmsg(svc_db));
		result = -1;
		goto end;
	}

	if (db_uid == GLOBAL_USER) {
		ret = sqlite3_bind_int(stmt, 2, uid);
		if (ret != SQLITE_OK) {
			_E("sqlite3_bind_int() error - %s(%d)",
					sqlite3_errmsg(svc_db), ret);
			result = -1;
			goto end;
		}
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW) {
		if (ret != SQLITE_DONE) {
			_W("sqlite3 step() error: %d(%s)",
					ret, sqlite3_errmsg(svc_db));
		}
		result = -1;
		goto end;
	}

	real_appid = (const char *)sqlite3_column_text(stmt, 0);
	if (real_appid) {
		*appid = strdup(real_appid);
		if (*appid == NULL) {
			_E("out of memory");
			result = -1;
			goto end;
		}
	}

	SECURE_LOGD("alias_appid: %s, appid: %s", alias_appid, real_appid);

end:
	sqlite3_finalize(stmt);
	__fini(&svc_db);

	return result;
}

int _svc_db_get_appid_from_alias_info(const char *alias_appid, char **appid,
		uid_t uid)
{
	int ret;

	ret = __get_appid_from_alias_info(alias_appid, appid, uid, uid);
	if (ret < 0) {
		ret = __get_appid_from_alias_info(alias_appid, appid, uid,
				GLOBAL_USER);
	}

	return ret;
}

static int __get_alias_info_list(uid_t uid, uid_t db_uid, GHashTable *list)
{
	int ret;
	sqlite3_stmt *stmt = NULL;
	const char *query;
	const char *alias_id;
	const char *id;
	struct alias_info_s *info;
	sqlite3 *svc_db = NULL;

	if (__init(db_uid, true, &svc_db) < 0)
		return -1;

	if (db_uid == GLOBAL_USER) {
		query = "SELECT alias_appid, appid FROM alias_info WHERE " \
			 "alias_info.appid NOT IN " \
			 "(SELECT appid FROM alias_info_for_uid WHERE " \
			 "uid = ?);";
	} else {
		query = "SELECT alias_appid, appid FROM alias_info WHERE " \
			 "enable = 'true';";
	}

	ret = sqlite3_prepare_v2(svc_db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_E("sqlite3_prepare_v2() error - %s(%d)",
				sqlite3_errmsg(svc_db), ret);
		__fini(&svc_db);
		return -1;
	}

	if (db_uid == GLOBAL_USER) {
		ret = sqlite3_bind_int(stmt, 1, uid);
		if (ret != SQLITE_OK) {
			_E("sqlite3_bind_int() error - %s(%d)",
					sqlite3_errmsg(svc_db), ret);
			sqlite3_finalize(stmt);
			__fini(&svc_db);
			return -1;
		}
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		alias_id = (const char *)sqlite3_column_text(stmt, 0);
		if (alias_id == NULL) {
			_E("Failed to get alias_appid");
			break;
		}

		id = (const char *)sqlite3_column_text(stmt, 1);
		if (id == NULL) {
			_E("Failed to get appid");
			break;
		}

		info = malloc(sizeof(struct alias_info_s));
		if (info == NULL) {
			_E("out of memory");
			break;
		}

		info->alias_appid = strdup(alias_id);
		if (info->alias_appid == NULL) {
			_E("out of memory");
			free(info);
			break;
		}

		info->appid = strdup(id);
		if (info->appid == NULL) {
			_E("out of memory");
			free(info->alias_appid);
			free(info);
			break;
		}

		g_hash_table_insert(list, info->alias_appid, info);

	}

	sqlite3_finalize(stmt);
	__fini(&svc_db);

	return 0;
}

static void __destroy_alias_info(gpointer data)
{
	struct alias_info_s *info = (struct alias_info_s *)data;

	if (info == NULL)
		return;

	if (info->appid)
		free(info->appid);
	if (info->alias_appid)
		free(info->alias_appid);
	free(info);
}

int _svc_db_foreach_alias_info(void (*callback)(const char *alias_appid,
			const char *appid, void *data),
		uid_t uid, void *user_data)
{
	int ret;
	GHashTable *list;
	GHashTableIter iter;
	gpointer value = NULL;
	struct alias_info_s *info;
	bool invoked = false;

	list = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			__destroy_alias_info);
	if (list == NULL) {
		_E("out of memory");
		return -1;
	}

	ret = __get_alias_info_list(uid, uid, list);
	if (ret == 0 && uid != GLOBAL_USER)
		ret = __get_alias_info_list(uid, GLOBAL_USER, list);

	if (ret != 0) {
		_E("Failed to get alias info list");
		g_hash_table_destroy(list);
		return -1;
	}

	g_hash_table_iter_init(&iter, list);
	while (g_hash_table_iter_next(&iter, NULL, &value)) {
		info = (struct alias_info_s *)value;
		if (info)
			callback(info->alias_appid, info->appid, user_data);
		invoked = true;
		value = NULL;
	}
	g_hash_table_destroy(list);

	if (!invoked)
		_W("alias info is empty");

	return 0;
}

static int __enable_disable_alias_info(const char *appid, uid_t uid,
		uid_t db_uid, bool enable)
{
	int ret;
	int result = 0;
	sqlite3_stmt *stmt = NULL;
	const char *query;
	const char *value;
	sqlite3 *svc_db = NULL;

	if (appid == NULL) {
		_E("Invalid parameter");
		return -1;
	}

	if (__init(db_uid, false, &svc_db) < 0)
		return -1;

	if (enable)
		value = "true";
	else
		value = "false";

	if (db_uid == GLOBAL_USER) {
		query = "INSERT OR REPLACE INTO alias_info_for_uid(appid, uid, is_enabled) " \
			 "values((SELECT appid FROM alias_info WHERE appid = ?), ?, ?);";
	} else {
		query = "UPDATE alias_info set enable = ? WHERE appid = ?;";
	}

	ret = sqlite3_prepare_v2(svc_db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_E("sqlite3_prepare_v2() error - %s(%d)",
				sqlite3_errmsg(svc_db), ret);
		__fini(&svc_db);
		return -1;
	}

	if (db_uid == GLOBAL_USER) {
		ret = sqlite3_bind_text(stmt, 1, appid, -1, SQLITE_TRANSIENT);
		if (ret != SQLITE_OK) {
			_E("sqlite3_bind_text() error - %s(%d)",
					sqlite3_errmsg(svc_db), ret);
			result = -1;
			goto end;
		}

		ret = sqlite3_bind_int(stmt, 2, uid);
		if (ret != SQLITE_OK) {
			_E("sqlite3_bind_int() error - %s(%d)",
					sqlite3_errmsg(svc_db), ret);
			result = -1;
			goto end;
		}

		ret = sqlite3_bind_text(stmt, 3, value, -1, SQLITE_TRANSIENT);
		if (ret != SQLITE_OK) {
			_E("sqlite3_bind_text() error - %s(%d)",
					sqlite3_errmsg(svc_db), ret);
			result = -1;
			goto end;
		}
	} else {
		ret = sqlite3_bind_text(stmt, 1, value, -1, SQLITE_TRANSIENT);
		if (ret != SQLITE_OK) {
			_E("sqlite3_bind_text() error - %s(%d)",
					sqlite3_errmsg(svc_db), ret);
			result = -1;
			goto end;
		}

		ret = sqlite3_bind_text(stmt, 2, appid, -1, SQLITE_TRANSIENT);
		if (ret != SQLITE_OK) {
			_E("sqlite3_bind_text() error - %s(%d)",
					sqlite3_errmsg(svc_db), ret);
			result = -1;
			goto end;
		}
	}

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_DONE) {
		_W("sqlite3_step() error - %s(%d)",
				sqlite3_errmsg(svc_db), ret);
		result = -1;
	}

end:
	sqlite3_finalize(stmt);
	__fini(&svc_db);

	return result;
}

int _svc_db_enable_alias_info(const char *appid, uid_t uid)
{
	int ret;

	ret = __enable_disable_alias_info(appid, uid, uid, true);
	if (ret < 0) {
		ret = __enable_disable_alias_info(appid, uid,
				GLOBAL_USER, true);
	}

	return ret;
}

int _svc_db_disable_alias_info(const char *appid, uid_t uid)
{
	int ret;

	ret = __enable_disable_alias_info(appid, uid, uid, false);
	if (ret < 0) {
		ret = __enable_disable_alias_info(appid, uid,
				GLOBAL_USER, false);
	}

	return ret;
}

static int __get_alias_info_list_by_appid(const char *appid, uid_t uid,
		uid_t db_uid, GHashTable *list)
{
	int ret;
	sqlite3_stmt *stmt = NULL;
	const char *query;
	const char *alias_id;
	const char *id;
	struct alias_info_s *info;
	sqlite3 *svc_db = NULL;

	if (__init(db_uid, true, &svc_db) < 0)
		return -1;

	if (db_uid == GLOBAL_USER) {
		query = "SELECT alias_appid, appid FROM alias_info WHERE " \
			 "alias_info.appid = ? AND " \
			 "alias_info.appid NOT IN " \
			 "(SELECT appid FROM alias_info_for_uid WHERE "\
			 "uid = ?);";
	} else {
		query = "SELECT alias_appid, appid FROM alias_info WHERE " \
			 "appid = ? AND enable = 'true';";
	}

	ret = sqlite3_prepare_v2(svc_db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_E("sqlite3_prepare_v2() error - %s(%d)",
				sqlite3_errmsg(svc_db), ret);
		__fini(&svc_db);
		return -1;
	}

	ret = sqlite3_bind_text(stmt, 1, appid, -1, SQLITE_TRANSIENT);
	if (ret != SQLITE_OK) {
		_E("sqlite3_bind_text() error - %s(%d)",
				sqlite3_errmsg(svc_db), ret);
		sqlite3_finalize(stmt);
		__fini(&svc_db);
		return -1;
	}

	if (db_uid == GLOBAL_USER) {
		ret = sqlite3_bind_int(stmt, 2, uid);
		if (ret != SQLITE_OK) {
			_E("sqlite3_bind_int() error - %s(%d)",
					sqlite3_errmsg(svc_db), ret);
			sqlite3_finalize(stmt);
			__fini(&svc_db);
			return -1;
		}
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		alias_id = (const char *)sqlite3_column_text(stmt, 0);
		if (alias_id == NULL) {
			_E("Failed to get alias_appid");
			break;
		}

		id = (const char *)sqlite3_column_text(stmt, 1);
		if (id == NULL) {
			_E("Failed to get appid");
			break;
		}

		info = malloc(sizeof(struct alias_info_s));
		if (info == NULL) {
			_E("out of memory");
			break;
		}

		info->alias_appid = strdup(alias_id);
		if (info->alias_appid == NULL) {
			_E("out of memory");
			free(info);
			break;
		}

		info->appid = strdup(id);
		if (info->appid == NULL) {
			_E("out of memory");
			free(info->alias_appid);
			free(info);
			break;
		}

		g_hash_table_insert(list, info->alias_appid, info);

	}

	sqlite3_finalize(stmt);
	__fini(&svc_db);

	return 0;
}

int _svc_db_foreach_alias_info_by_appid(int (*callback)(
			const char *alias_appid, const char *appid, void *data),
		const char *appid, uid_t uid, void *user_data)
{
	int ret;
	GHashTable *list;
	GHashTableIter iter;
	gpointer value = NULL;
	struct alias_info_s *info;
	bool invoked = false;

	list = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			__destroy_alias_info);
	if (list == NULL) {
		_E("out of memory");
		return -1;
	}

	ret = __get_alias_info_list_by_appid(appid, uid, uid, list);
	if (ret == 0 && uid != GLOBAL_USER) {
		ret = __get_alias_info_list_by_appid(appid, uid,
				GLOBAL_USER, list);
	}

	if (ret != 0) {
		_E("Failed to get alias info list");
		g_hash_table_destroy(list);
		return -1;
	}

	g_hash_table_iter_init(&iter, list);
	while (g_hash_table_iter_next(&iter, NULL, &value)) {
		info = (struct alias_info_s *)value;
		if (info)
			callback(info->alias_appid, info->appid, user_data);
		invoked = true;
		value = NULL;
	}
	g_hash_table_destroy(list);

	if (!invoked)
		_W("alias info is empty");

	return 0;
}

static int __get_allowed_info_list(const char *appid, uid_t uid,
		uid_t db_uid, GHashTable *tbl)
{
	int ret;
	sqlite3_stmt *stmt = NULL;
	const char *query;
	const char *id;
	const char *allowed_id;
	struct allowed_info_s *info;
	GList *list;
	GList *iter;
	sqlite3 *svc_db = NULL;

	if (__init(db_uid, true, &svc_db) < 0)
		return -1;

	if (appid) {
		query = "SELECT appid, allowed_appid FROM allowed_info WHERE " \
			 "appid = ?;";
	} else {
		query = "SELECT appid, allowed_appid FROM allowed_info;";
	}

	ret = sqlite3_prepare_v2(svc_db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		_E("sqlite3_prepare_v2() error - %s(%d)",
				sqlite3_errmsg(svc_db), ret);
		__fini(&svc_db);
		return -1;
	}

	if (appid) {
		ret = sqlite3_bind_text(stmt, 1, appid, -1, SQLITE_TRANSIENT);
		if (ret != SQLITE_OK) {
			_E("sqlite3_bind_text() error - %s(%d)",
					sqlite3_errmsg(svc_db), ret);
			sqlite3_finalize(stmt);
			__fini(&svc_db);
			return -1;
		}
	}

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		id = (const char *)sqlite3_column_text(stmt, 0);
		if (id == NULL) {
			_E("Failed to get appid");
			break;
		}

		allowed_id = (const char *)sqlite3_column_text(stmt, 1);
		if (allowed_id == NULL) {
			_E("Failed to get allowed appid");
			break;
		}

		list = g_hash_table_lookup(tbl, id);
		if (list) {
			iter = g_list_first(list);
			if (iter) {
				info = (struct allowed_info_s *)iter->data;
				if (info && info->uid != db_uid)
					continue;
			}
		}

		info = malloc(sizeof(struct allowed_info_s));
		if (info == NULL) {
			_E("out of memory");
			break;
		}

		info->uid = db_uid;
		info->appid = strdup(id);
		if (info->appid == NULL) {
			_E("out of memory");
			free(info);
			break;
		}

		info->allowed_appid = strdup(allowed_id);
		if (info->allowed_appid == NULL) {
			_E("out of memory");
			free(info->appid);
			free(info);
			break;
		}

		if (list) {
			list = g_list_append(list, info);
		} else {
			list = g_list_append(list, info);
			g_hash_table_insert(tbl, info->appid, list);
		}
	}

	sqlite3_finalize(stmt);
	__fini(&svc_db);

	return 0;
}

static void __destroy_allowed_info(gpointer data)
{
	struct allowed_info_s *info = (struct allowed_info_s *)data;

	if (info == NULL)
		return;

	if (info->allowed_appid)
		free(info->allowed_appid);
	if (info->appid)
		free(info->appid);
	free(info);
}

static void __destroy_allowed_info_list(gpointer data)
{
	GList *list = (GList *)data;

	if (list == NULL)
		return;

	g_list_free_full(list, __destroy_allowed_info);
}

int _svc_db_foreach_allowed_info_by_appid(int (*callback)(const char *appid,
			const char *allowed_appid, void *data),
		const char *appid, uid_t uid, void *user_data)
{
	int ret;
	GHashTable *tbl;
	GHashTableIter hash_iter;
	gpointer value = NULL;
	struct allowed_info_s *info;
	bool invoked = false;
	GList *list;
	GList *iter;

	tbl = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			__destroy_allowed_info_list);
	if (tbl == NULL) {
		_E("out of memory");
		return -1;
	}

	ret = __get_allowed_info_list(appid, uid, uid, tbl);
	if (ret == 0 && uid != GLOBAL_USER)
		ret = __get_allowed_info_list(appid, uid, GLOBAL_USER, tbl);

	if (ret != 0) {
		_E("Failed to get allowed info table");
		g_hash_table_destroy(tbl);
		return -1;
	}

	g_hash_table_iter_init(&hash_iter, tbl);
	while (g_hash_table_iter_next(&hash_iter, NULL, &value)) {
		list = (GList *)value;
		if (list) {
			iter = g_list_first(list);
			while (iter) {
				info = (struct allowed_info_s *)iter->data;
				if (info)
					callback(info->appid, info->allowed_appid, user_data);
				iter = g_list_next(iter);
			}
		}
		invoked = true;
		value = NULL;
	}
	g_hash_table_destroy(tbl);

	if (!invoked)
		_W("allowed info is empty");

	return 0;
}

int _svc_db_foreach_allowed_info(int (*callback)(const char *appid,
			const char *allowed_appid, void *data),
		uid_t uid, void *user_data)
{
	return _svc_db_foreach_allowed_info_by_appid(callback, NULL,
			uid, user_data);
}
