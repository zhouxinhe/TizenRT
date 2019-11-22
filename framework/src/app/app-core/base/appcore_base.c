/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd. All rights reserved.
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

#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <malloc.h>
#include <locale.h>
#include <libintl.h>
#include <linux/limits.h>
// #include <glib.h>
// #include <gio/gio.h>
#include <sys/time.h>
// #include <dlfcn.h>
#include <vconf.h>
#include <aul.h>
#include <bundle_internal.h>
// #include <sensor_internal.h>
// #include <ttrace.h>
// #include <system_info.h>

#include "appcore_base.h"
#include "appcore_base_private.h"
#include "appcore_watchdog.h"

#define PATH_LOCALE "locale"
#define RESOURCED_FREEZER_PATH "/Org/Tizen/ResourceD/Freezer"
#define RESOURCED_FREEZER_INTERFACE "org.tizen.resourced.freezer"
#define RESOURCED_FREEZER_SIGNAL "FreezerState"
#define SQLITE_FLUSH_MAX (1024 * 1024)

typedef struct _appcore_base_context {
	appcore_base_ops ops;
	void *data;
	int argc;
	char **argv;
	unsigned int tid;
	bool suspended_state;
	bool allowed_bg;
	bool dirty;
	unsigned int sid;
} appcore_base_context;

typedef struct _appcore_base_event_node {
	int type;
	appcore_base_event_cb cb;
	void *data;
} appcore_base_event_node;

typedef struct _appcore_base_rotation {
	int conn;
	int lock;
	int ref;
	enum appcore_base_rm rm;
	int charger_status;
	bool initialized;
} appcore_base_rotation;

struct lang_info_s {
	char *parent;
	GList *list;
};

static appcore_base_context __context;
static GList *__events;
static GDBusConnection *__bus;
static unsigned int __suspend_dbus_handler_initialized;
static char *__locale_dir;
static appcore_base_rotation __rotation;

appcore_base_tizen_profile_t appcore_base_get_tizen_profile(void)
{
	return TIZEN_PROFILE_WEARABLE;
}


static void __invoke_callback(void *event, int type)
{
	GList *iter = __events;

	while (iter) {
		appcore_base_event_node *node = iter->data;

		if (node->type == type)
			node->cb(event, node->data);
		iter = g_list_next(iter);
	}
}

static bool __exist_callback(int type)
{
	GList *iter = __events;

	while (iter) {
		appcore_base_event_node *node = iter->data;

		if (node->type == type)
			return true;

		iter = g_list_next(iter);
	}

	return false;
}

static enum appcore_base_rm __get_rm(sensor_data_t data)
{
#if 0
	int event;
	enum appcore_base_rm rm;

	if (data.value_count <= 0) {
		_ERR("Failed to get sensor data");
		return APPCORE_BASE_RM_UNKNOWN;
	}

	event = data.values[0];
	switch (event) {
	case AUTO_ROTATION_DEGREE_0:
		rm = APPCORE_BASE_RM_PORTRAIT_NORMAL;
		break;
	case AUTO_ROTATION_DEGREE_90:
		rm = APPCORE_BASE_RM_LANDSCAPE_NORMAL;
		break;
	case AUTO_ROTATION_DEGREE_180:
		rm = APPCORE_BASE_RM_PORTRAIT_REVERSE;
		break;
	case AUTO_ROTATION_DEGREE_270:
		rm = APPCORE_BASE_RM_LANDSCAPE_REVERSE;
		break;
	default:
		rm = APPCORE_BASE_RM_UNKNOWN;
		break;
	}

	return rm;
#else
	return APPCORE_BASE_RM_PORTRAIT_NORMAL;
#endif
}

static void __lock_cb(keynode_t *node, void *user_data)
{
	bool r;
	sensor_data_t data;
	enum appcore_base_rm rm;

	__rotation.lock = !vconf_keynode_get_bool(node);
	if (__rotation.lock) {
		_DBG("Rotation locked");
		rm = APPCORE_BASE_RM_PORTRAIT_NORMAL;
	} else {
		_DBG("Rotation unlocked");
		r = sensord_get_data(__rotation.conn, AUTO_ROTATION_SENSOR, &data);
		if (!r) {
			_ERR("Failed to get sensor data");
			return;
		}

		rm = __get_rm(data);
		if (rm == APPCORE_BASE_RM_UNKNOWN) {
			_ERR("Unknown mode");
			return;
		}
	}

	if (__rotation.rm == rm)
		return;

	_DBG("Rotation: %d -> %d", __rotation.rm, rm);
	__rotation.rm = rm;
	__invoke_callback((void *)&__rotation.rm, APPCORE_BASE_EVENT_DEVICE_ORIENTATION_CHANGED);
}

static void __auto_rotation_changed_cb(sensor_t sensor, unsigned int event_type,
		sensor_data_t *data, void *user_data)
{
	enum appcore_base_rm rm;

	if (data == NULL)
		return;

	if (__rotation.lock)
		return;

	if (event_type != AUTO_ROTATION_CHANGE_STATE_EVENT)
		return;

	rm = __get_rm(*data);
	if (rm == APPCORE_BASE_RM_UNKNOWN) {
		_ERR("Unknown mode");
		return;
	}

	_DBG("Rotation: %d -> %d", __rotation.rm, rm);
	__rotation.rm = rm;
	__invoke_callback((void *)&__rotation.rm, APPCORE_BASE_EVENT_DEVICE_ORIENTATION_CHANGED);
}

static void __fini_rotation(void)
{
	if (!__rotation.initialized)
		return;

	vconf_ignore_key_changed(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL, __lock_cb);
	sensord_unregister_event(__rotation.conn, AUTO_ROTATION_CHANGE_STATE_EVENT);
	sensord_stop(__rotation.conn);
	sensord_disconnect(__rotation.conn);

	__rotation.lock = 0;
	__rotation.initialized = false;
}

static void __init_rotation(void)
{
	sensor_t sensor;
	int lock;
	bool r;

	if (__rotation.initialized)
		return;

	sensor = sensord_get_sensor(AUTO_ROTATION_SENSOR);
	__rotation.conn = sensord_connect(sensor);
	if (__rotation.conn < 0) {
		_ERR("Failed to connect sensord");
		return;
	}

	r = sensord_register_event(__rotation.conn, AUTO_ROTATION_CHANGE_STATE_EVENT,
			SENSOR_INTERVAL_NORMAL, 0, __auto_rotation_changed_cb, NULL);
	if (!r) {
		_ERR("Failed to register auto rotation change event");
		sensord_disconnect(__rotation.conn);
		return;
	}

	r = sensord_start(__rotation.conn, 0);
	if (!r) {
		_ERR("Failed to start sensord");
		sensord_unregister_event(__rotation.conn, AUTO_ROTATION_CHANGE_STATE_EVENT);
		sensord_disconnect(__rotation.conn);
		return;
	}

	lock = 0;
	vconf_get_bool(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL, &lock);
	vconf_notify_key_changed(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL, __lock_cb, NULL);

	__rotation.lock = !lock;
	__rotation.initialized = true;
}

static void __charger_status_changed_cb(keynode_t *keynode, void *user_data)
{
	if (TIZEN_FEATURE_CHARGER_STATUS) {
		__rotation.charger_status = vconf_keynode_get_int(keynode);
		if (__rotation.charger_status) {
			if (__rotation.ref)
				__init_rotation();
		} else {
			if (__rotation.ref)
				__fini_rotation();
		}
		_DBG("charger status(%d)", __rotation.charger_status);
	}
}

static void __unregister_rotation_changed_event(void)
{
	if (!__rotation.ref)
		return;

	__rotation.ref--;
	if (__rotation.ref > 1)
		return;

	__fini_rotation();
	if (TIZEN_FEATURE_CHARGER_STATUS) {
		vconf_ignore_key_changed(VCONFKEY_SYSMAN_CHARGER_STATUS,
				__charger_status_changed_cb);
	}

	__rotation.ref = 0;
}

static void __register_rotation_changed_event(void)
{
	if (__rotation.ref) {
		__rotation.ref++;
		return;
	}

	if (TIZEN_FEATURE_CHARGER_STATUS) {
		vconf_get_int(VCONFKEY_SYSMAN_CHARGER_STATUS,
				&__rotation.charger_status);
		vconf_notify_key_changed(VCONFKEY_SYSMAN_CHARGER_STATUS,
				__charger_status_changed_cb, NULL);
		if (__rotation.charger_status)
			__init_rotation();
	} else {
		__init_rotation();
	}

	__rotation.ref++;
}

static void __on_low_memory(keynode_t *key, void *data)
{
	int val;

	val = vconf_keynode_get_int(key);

	if (val >= VCONFKEY_SYSMAN_LOW_MEMORY_SOFT_WARNING) {
		__invoke_callback(&val, APPCORE_BASE_EVENT_LOW_MEMORY);
		malloc_trim(0);
	}
}

static void __on_low_battery(keynode_t *key, void *data)
{
	int val;

	val = vconf_keynode_get_int(key);

	if (val <= VCONFKEY_SYSMAN_BAT_CRITICAL_LOW)
		__invoke_callback(&val, APPCORE_BASE_EVENT_LOW_BATTERY);
}

static void __destroy_lang_info(gpointer data)
{
	struct lang_info_s *info = (struct lang_info_s *)data;

	if (info == NULL)
		return;

	if (info->list)
		g_list_free_full(info->list, free);
	if (info->parent)
		free(info->parent);
	free(info);
}

static struct lang_info_s *__create_lang_info(const char *lang)
{
	struct lang_info_s *info;

	info = calloc(1, sizeof(struct lang_info_s));
	if (info == NULL) {
		_ERR("Out of memory");
		return NULL;
	}

	info->parent = strdup(lang);
	if (info->parent == NULL) {
		_ERR("Out of memory");
		free(info);
		return NULL;
	}

	return info;
}

static int __compare_langs(gconstpointer a, gconstpointer b)
{
	if (!a || !b)
		return -1;

	return strcmp(a, b);
}

static char *__get_string_before(const char *str, const char *delim)
{
	char *new_str;
	char *dup_str;
	char *token;

	dup_str = strdup(str);
	if (dup_str == NULL)
		return NULL;

	token = strtok(dup_str, delim);
	if (token == NULL) {
		free(dup_str);
		return NULL;
	}

	new_str = strdup(token);
	free(dup_str);

	return new_str;
}

static GHashTable *__get_lang_table(void)
{
	GHashTable *table;
	DIR *dp;
	struct dirent *dentry;
	char buf[PATH_MAX];
	struct stat stat_buf;
	int ret;
	char *parent_lang;
	struct lang_info_s *info;

	if (__locale_dir == NULL || __locale_dir[0] == '\0')
		return NULL;

	table = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, __destroy_lang_info);
	if (table == NULL) {
		_ERR("Out of memory");
		return NULL;
	}

	dp = opendir(__locale_dir);
	if (dp == NULL) {
		g_hash_table_destroy(table);
		return NULL;
	}

	while ((dentry = readdir(dp)) != NULL) {
		if (!strcmp(dentry->d_name, ".") ||
				!strcmp(dentry->d_name, ".."))
			continue;

		snprintf(buf, sizeof(buf), "%s/%s",
				__locale_dir, dentry->d_name);
		ret = stat(buf, &stat_buf);
		if (ret != 0 || !S_ISDIR(stat_buf.st_mode))
			continue;

		parent_lang = __get_string_before(dentry->d_name, "_");
		if (parent_lang == NULL) {
			_ERR("Out of memory");
			break;
		}

		info = g_hash_table_lookup(table, parent_lang);
		if (info == NULL) {
			info = __create_lang_info(parent_lang);
			if (info == NULL) {
				free(parent_lang);
				break;
			}
			g_hash_table_insert(table, info->parent, info);
		}
		info->list = g_list_append(info->list, strdup(dentry->d_name));
		free(parent_lang);
	}
	closedir(dp);

	return table;
}

static GList *__append_langs(const char *lang, GList *list, GHashTable *table)
{
	struct lang_info_s *info;
	GList *found;
	char *parent_lang = NULL;
	char *extract_lang;

	if (lang == NULL)
		return list;

	list = g_list_append(list, strdup(lang));

	extract_lang = __get_string_before(lang, ".");
	if (extract_lang == NULL)
		return list;

	found = g_list_find_custom(list, extract_lang, __compare_langs);
	if (found) {
		list = g_list_remove_link(list, found);
		list = g_list_concat(list, found);
		goto end;
	}

	parent_lang = __get_string_before(extract_lang, "_");
	if (parent_lang == NULL)
		goto end;

	info = g_hash_table_lookup(table, parent_lang);
	if (info == NULL)
		goto end;

	found = g_list_find_custom(info->list, extract_lang, __compare_langs);
	if (found) {
		info->list = g_list_remove_link(info->list, found);
		list = g_list_concat(list, found);
		goto end;
	}

	found = g_list_find_custom(info->list, parent_lang, __compare_langs);
	if (found) {
		info->list = g_list_remove_link(info->list, found);
		list = g_list_concat(list, found);
		goto end;
	}

	found = g_list_first(info->list);
	if (found) {
		info->list = g_list_remove_link(info->list, found);
		list = g_list_concat(list, found);
	}

end:
	if (extract_lang)
		free(extract_lang);
	if (parent_lang)
		free(parent_lang);

	return list;
}

static GList *__split_language(const char *lang)
{
	GList *list = NULL;
	char *dup_lang;
	char *token;

	dup_lang = strdup(lang);
	if (dup_lang == NULL) {
		_ERR("Out of memory");
		return NULL;
	}

	token = strtok(dup_lang, ":");
	while (token != NULL) {
		list = g_list_append(list, strdup(token));
		token = strtok(NULL, ":");
	}
	free(dup_lang);

	return list;
}

static GList *__append_default_langs(GList *list)
{
	const char *langs[] = {"en_US", "en_GB", "en"};
	unsigned int i;
	GList *found;

	for (i = 0; i < (sizeof(langs) / sizeof(langs[0])); i++) {
		found = g_list_find_custom(list, langs[i], __compare_langs);
		if (found == NULL)
			list = g_list_append(list, strdup(langs[i]));
	}

	return list;
}

static char *__get_language(const char *lang)
{
	GHashTable *table;
	GList *list;
	GList *lang_list = NULL;
	GList *iter;
	char *language;
	char buf[LINE_MAX] = {'\0'};
	size_t n;

	list = __split_language(lang);
	if (list == NULL)
		return NULL;

	table = __get_lang_table();
	if (table == NULL) {
		g_list_free_full(list, free);
		return NULL;
	}

	iter = g_list_first(list);
	while (iter) {
		language = (char *)iter->data;
		lang_list = __append_langs(language, lang_list, table);
		iter = g_list_next(iter);
	}
	g_list_free_full(list, free);
	g_hash_table_destroy(table);

	lang_list = __append_default_langs(lang_list);
	iter = g_list_first(lang_list);
	while (iter) {
		language = (char *)iter->data;
		if (language) {
			if (buf[0] == '\0') {
				snprintf(buf, sizeof(buf), "%s", language);
			} else {
				n = sizeof(buf) - strlen(buf) - 1;
				strncat(buf, ":", n);
				n = sizeof(buf) - strlen(buf) - 1;
				strncat(buf, language, n);
			}
		}
		iter = g_list_next(iter);
	}
	g_list_free_full(lang_list, free);

	return strdup(buf);
}

static void __update_lang(void)
{
	char *language;
	char *lang;
	char *r;

	lang = vconf_get_str(VCONFKEY_LANGSET);
	if (lang) {
		/* TODO: Use VCONFKEY_SETAPPL_LANGUAGES key */
		language = __get_language(lang);
		if (language) {
			_DBG("*****language(%s)", language);
			setenv("LANGUAGE", language, 1);
			free(language);
		} else {
			setenv("LANGUAGE", lang, 1);
		}
		setenv("LANG", lang, 1);
		setenv("LC_MESSAGES", lang, 1);
		setenv("LC_ALL", lang, 1);
		r = setlocale(LC_ALL, "");
		if (r == NULL) {
			r = setlocale(LC_ALL, "en_US.UTF-8");
			if (r != NULL) {
				_DBG("*****appcore setlocale=%s\n", r);
			} else {
				_DBG("*****appcore setlocale=\"C\"");
				setenv("LC_ALL", "C", 1);
				r = setlocale(LC_ALL, "");
				if (r == NULL)
					_ERR("failed to setlocale");
			}
		}
		free(lang);
	}
}

static void __update_region(void)
{
	char *region;
	char *r;

	region = vconf_get_str(VCONFKEY_REGIONFORMAT);
	if (region) {
		setenv("LC_CTYPE", region, 1);
		setenv("LC_NUMERIC", region, 1);
		setenv("LC_TIME", region, 1);
		setenv("LC_COLLATE", region, 1);
		setenv("LC_MONETARY", region, 1);
		setenv("LC_PAPER", region, 1);
		setenv("LC_NAME", region, 1);
		setenv("LC_ADDRESS", region, 1);
		setenv("LC_TELEPHONE", region, 1);
		setenv("LC_MEASUREMENT", region, 1);
		setenv("LC_IDENTIFICATION", region, 1);
		r = setlocale(LC_ALL, "");
		if (r != NULL) {
			_DBG("*****appcore setlocale=%s\n", r);
		} else {
			_DBG("*****appcore setlocale=\"C\"");
			setenv("LC_ALL", "C", 1);
			r = setlocale(LC_ALL, "");
			if (r == NULL)
				_ERR("failed to setlocale");
		}

		free(region);
	}
}

static void __on_language_change(keynode_t *key, void *data)
{
	char *val;

	if (__context.sid) {
		g_source_remove(__context.sid);
		__context.sid = 0;
	}

	val = vconf_keynode_get_str(key);

	__update_lang();
	__invoke_callback((void *)val, APPCORE_BASE_EVENT_LANG_CHANGE);
}

static void __on_region_change(keynode_t *key, void *data)
{
	char *val;
	const char *name;

	name = vconf_keynode_get_name(key);
	if (name == NULL)
		return;

	if (strcmp(name, VCONFKEY_REGIONFORMAT) &&
			strcmp(name, VCONFKEY_REGIONFORMAT_TIME1224))
		return;

	val = vconf_get_str(VCONFKEY_REGIONFORMAT);

	__update_region();
	__invoke_callback((void *)val, APPCORE_BASE_EVENT_REGION_CHANGE);
	free(val);
}

static gboolean __invoke_lang_change(gpointer data)
{
	const char *lang;

	__context.sid = 0;

	lang = getenv("LANG");
	if (!lang)
		return G_SOURCE_REMOVE;

	__invoke_callback((void *)lang, APPCORE_BASE_EVENT_LANG_CHANGE);

	return G_SOURCE_REMOVE;
}

static void __verify_language(void)
{
	char *lang;
	const char *env_lang;

	env_lang = getenv("LANG");
	if (!env_lang)
		return;

	lang = vconf_get_str(VCONFKEY_LANGSET);
	if (!lang)
		return;

	if (strcmp(env_lang, lang) != 0) {
		_INFO("LANG(%s), LANGSET(%s)", env_lang, lang);
		__context.sid = g_idle_add(__invoke_lang_change, NULL);
	}

	free(lang);
}

static gboolean __flush_memory(gpointer data)
{
	int suspend = APPCORE_BASE_SUSPENDED_STATE_WILL_ENTER_SUSPEND;

	if (__context.ops.trim_memory)
		__context.ops.trim_memory(__context.data);

	__context.tid = 0;

	if (!__context.allowed_bg && !__context.suspended_state) {
		_DBG("[__SUSPEND__] flush case");
		__invoke_callback((void *)&suspend, APPCORE_BASE_EVENT_SUSPENDED_STATE_CHANGE);
		__context.suspended_state = true;
	}

	return FALSE;
}

static void __add_suspend_timer(void)
{
	__context.tid = g_timeout_add_seconds(5, __flush_memory, NULL);
}

static void __remove_suspend_timer(void)
{
	if (__context.tid > 0) {
		g_source_remove(__context.tid);
		__context.tid = 0;
	}
}

static void __on_receive_suspend_signal(GDBusConnection *connection,
					const gchar *sender_name,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *signal_name,
					GVariant *parameters,
					gpointer user_data)
{
	int suspend = APPCORE_BASE_SUSPENDED_STATE_DID_EXIT_FROM_SUSPEND;
	int pid;
	int status;

	if (g_strcmp0(signal_name, RESOURCED_FREEZER_SIGNAL) == 0) {
		g_variant_get(parameters, "(ii)", &status, &pid);
		if (pid == getpid() && status == 0) {
			if (!__context.allowed_bg && __context.suspended_state) {
				__remove_suspend_timer();
				__invoke_callback((void *)&suspend, APPCORE_BASE_EVENT_SUSPENDED_STATE_CHANGE);
				__context.suspended_state = false;
				__add_suspend_timer();
			}
		}
	}
}

static int __init_suspend_dbus_handler(void)
{
	GError *err = NULL;

	if (__suspend_dbus_handler_initialized)
		return 0;

	if (!__bus) {
		__bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (!__bus) {
			_ERR("Failed to connect to the D-BUS daemon: %s",
						err->message);
			g_error_free(err);
			return -1;
		}
	}

	__suspend_dbus_handler_initialized = g_dbus_connection_signal_subscribe(
						__bus,
						NULL,
						RESOURCED_FREEZER_INTERFACE,
						RESOURCED_FREEZER_SIGNAL,
						RESOURCED_FREEZER_PATH,
						NULL,
						G_DBUS_SIGNAL_FLAGS_NONE,
						__on_receive_suspend_signal,
						NULL,
						NULL);
	if (__suspend_dbus_handler_initialized == 0) {
		_ERR("g_dbus_connection_signal_subscribe() is failed.");
		return -1;
	}

	_DBG("[__SUSPEND__] suspend signal initialized");

	return 0;
}

static void __fini_suspend_dbus_handler(void)
{
	if (__bus == NULL)
		return;

	if (__suspend_dbus_handler_initialized) {
		g_dbus_connection_signal_unsubscribe(__bus,
				__suspend_dbus_handler_initialized);
		__suspend_dbus_handler_initialized = 0;
	}

	g_object_unref(__bus);
	__bus = NULL;
}

static gboolean __init_suspend(gpointer data)
{
	__init_suspend_dbus_handler();
	return G_SOURCE_REMOVE;
}

static int __get_locale_resource_dir(char *locale_dir, int size)
{
	const char *res_path;

	res_path = aul_get_app_resource_path();
	if (res_path == NULL) {
		_ERR("Failed to get resource path");
		return -1;
	}

	snprintf(locale_dir, size, "%s" PATH_LOCALE, res_path);
	if (access(locale_dir, R_OK) != 0)
		_DBG("%s does not exist", locale_dir);

	return 0;
}

static int __get_app_name(const char *appid, char **name)
{
	char *name_token = NULL;

	if (appid == NULL)
		return -1;

	/* com.vendor.name -> name */
	name_token = strrchr(appid, '.');
	if (name_token == NULL)
		return -1;

	name_token++;

	*name = strdup(name_token);
	if (*name == NULL)
		return -1;

	return 0;
}

static int __set_i18n(const char *domain, const char *dir)
{
	char *r;

	if (domain == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (dir) {
		if (__locale_dir)
			free(__locale_dir);
		__locale_dir = strdup(dir);
	}

	__update_lang();
	__update_region();

	r = setlocale(LC_ALL, "");
	/* if locale is not set properly, try to set "en_US" again */
	if (r == NULL) {
		r = setlocale(LC_ALL, "en_US.UTF-8");
		if (r != NULL)
			_DBG("*****appcore setlocale=%s\n", r);
	}
	if (r == NULL) {
		_ERR("appcore: setlocale() error");
		_DBG("*****appcore setlocale=\"C\"");
		setenv("LC_ALL", "C", 1);
		r = setlocale(LC_ALL, "");
		if (r == NULL)
			_ERR("failed to setlocale");
	}

	r = bindtextdomain(domain, dir);
	if (r == NULL)
		_ERR("appcore: bindtextdomain() error");

	r = textdomain(domain);
	if (r == NULL)
		_ERR("appcore: textdomain() error");

	return 0;
}

EXPORT_API int appcore_base_on_set_i18n(void)
{
	int r;
	char locale_dir[PATH_MAX];
	char appid[PATH_MAX];
	char *name = NULL;

	r = aul_app_get_appid_bypid(getpid(), appid, PATH_MAX);
	if (r < 0) {
		_ERR("Failed to get application ID - pid(%d)", getpid());
		return -1;
	}

	r = __get_app_name(appid, &name);
	if (r < 0)
		return -1;

	r = __get_locale_resource_dir(locale_dir, sizeof(locale_dir));
	if (r < 0) {
		free(name);
		return -1;
	}

	r = __set_i18n(name, locale_dir);
	if (r < 0) {
		free(name);
		return -1;
	}

	free(name);

	return 0;
}

EXPORT_API int appcore_base_set_i18n(const char *domain_name, const char *dir_name)
{
	return __set_i18n(domain_name, dir_name);
}

static void __set_default_events(void)
{
	int r;

	vconf_notify_key_changed(VCONFKEY_LANGSET, __on_language_change, NULL);
	r = vconf_notify_key_changed(VCONFKEY_REGIONFORMAT, __on_region_change, NULL);
	if (r == 0)
		vconf_notify_key_changed(VCONFKEY_REGIONFORMAT_TIME1224, __on_region_change, NULL);
	vconf_notify_key_changed(VCONFKEY_SYSMAN_LOW_MEMORY, __on_low_memory, NULL);
}

static void __unset_default_events(void)
{
	int r;

	vconf_ignore_key_changed(VCONFKEY_LANGSET, __on_language_change);
	r = vconf_ignore_key_changed(VCONFKEY_REGIONFORMAT, __on_region_change);
	if (r == 0)
		vconf_ignore_key_changed(VCONFKEY_REGIONFORMAT_TIME1224, __on_region_change);
	vconf_ignore_key_changed(VCONFKEY_SYSMAN_LOW_MEMORY, __on_low_memory);
}

EXPORT_API int appcore_base_init(appcore_base_ops ops, int argc, char **argv, void *data)
{
	int i;
	int r;

	__context.ops = ops;
	__context.argc = argc;
	__context.argv = argv;
	__context.data = data;
	__context.tid = 0;
	__context.suspended_state = false;
	__context.allowed_bg = false;

	if (__context.ops.init)
		__context.ops.init(argc, argv, data);

	if (TIZEN_FEATURE_BACKGROUND_MANAGEMENT)
		g_idle_add(__init_suspend, NULL);

	if (!__context.dirty) {
		__context.dirty = true;

		for (i = APPCORE_BASE_EVENT_START + 1; i < APPCORE_BASE_EVENT_MAX; i++) {
			if (__exist_callback(i)) {
				if (__context.ops.set_event)
					__context.ops.set_event(i, __context.data);
			}
		}
	}

	__verify_language();
	__set_default_events();
	if (__context.ops.set_i18n)
		__context.ops.set_i18n(__context.data);

	if (__context.ops.create) {
		traceBegin(TTRACE_TAG_APPLICATION_MANAGER, "APPCORE:CREATE");
		r = __context.ops.create(__context.data);
		traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
		if (r < 0) {
			aul_status_update(STATUS_DYING);
			return 0;
		}
	}

	if (__context.ops.run)
		__context.ops.run(__context.data);

	return 0;
}

EXPORT_API void appcore_base_fini(void)
{
	int i;

	aul_status_update(STATUS_DYING);
	appcore_watchdog_disable();
	if (__context.ops.terminate) {
		traceBegin(TTRACE_TAG_APPLICATION_MANAGER, "APPCORE:TERMINATE");
		__context.ops.terminate(__context.data);
		traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
	}

	for (i = APPCORE_BASE_EVENT_START + 1; i < APPCORE_BASE_EVENT_MAX; i++) {
		if (__exist_callback(i)) {
			if (__context.ops.unset_event)
				__context.ops.unset_event(i, __context.data);
		}
	}

	__unset_default_events();

	if (__context.sid) {
		g_source_remove(__context.sid);
		__context.sid = 0;
	}

	g_list_free_full(__events, free);
	__events = NULL;

	if (TIZEN_FEATURE_BACKGROUND_MANAGEMENT)
		__fini_suspend_dbus_handler();

	if (__locale_dir) {
		free(__locale_dir);
		__locale_dir = NULL;
	}

	__context.dirty = false;

	if (__context.ops.finish)
		__context.ops.finish();
}

EXPORT_API int appcore_base_flush_memory(void)
{
	if (__context.ops.trim_memory)
		__context.ops.trim_memory(__context.data);

	return 0;
}

EXPORT_API int appcore_base_on_receive(aul_type type, bundle *b)
{
	const char *bg;
	int dummy = 0;

	switch (type) {
	case AUL_START:
		_DBG("[APP %d]     AUL event: AUL_START", getpid());
		if (TIZEN_FEATURE_BACKGROUND_MANAGEMENT) {
			bg = bundle_get_val(b, AUL_K_ALLOWED_BG);
			if (bg && !strcmp(bg, "ALLOWED_BG")) {
				_DBG("[__SUSPEND__] allowed background");
				__context.allowed_bg = true;
				__remove_suspend_timer();
			}
		}

		if (__context.ops.control) {
			traceBegin(TTRACE_TAG_APPLICATION_MANAGER, "APPCORE:RESET");
			__context.ops.control(b, __context.data);
			traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
		}
		break;
	case AUL_RESUME:
		_DBG("[APP %d]     AUL event: AUL_RESUME", getpid());
		if (TIZEN_FEATURE_BACKGROUND_MANAGEMENT) {
			bg = bundle_get_val(b, AUL_K_ALLOWED_BG);
			if (bg && !strcmp(bg, "ALLOWED_BG")) {
				_DBG("[__SUSPEND__] allowed background");
				__context.allowed_bg = true;
				__remove_suspend_timer();
			}
		}
		break;
	case AUL_TERMINATE:
		_DBG("[APP %d]     AUL event: AUL_TERMINATE", getpid());
		aul_status_update(STATUS_DYING);
		if (!__context.allowed_bg)
			__remove_suspend_timer();

		if (__context.ops.exit)
			__context.ops.exit(__context.data);
		break;
	case AUL_TERMINATE_BGAPP:
		_DBG("[APP %d]     AUL event: AUL_TERMINATE_BGAPP", getpid());
		if (!__context.allowed_bg)
			__remove_suspend_timer();
		break;
	case AUL_WAKE:
		_DBG("[APP %d]     AUL event: AUL_WAKE", getpid());
		if (TIZEN_FEATURE_BACKGROUND_MANAGEMENT) {
			if (!__context.allowed_bg &&
					__context.suspended_state) {
				int suspend = APPCORE_BASE_SUSPENDED_STATE_DID_EXIT_FROM_SUSPEND;
				__remove_suspend_timer();
				__invoke_callback((void *)&suspend, APPCORE_BASE_EVENT_SUSPENDED_STATE_CHANGE);
				__context.suspended_state = false;
			}
		}
		break;
	case AUL_SUSPEND:
		_DBG("[APP %d]     AUL event: AUL_SUSPEND", getpid());
		if (TIZEN_FEATURE_BACKGROUND_MANAGEMENT) {
			if (!__context.allowed_bg &&
					!__context.suspended_state) {
				__remove_suspend_timer();
				__flush_memory(NULL);
			}
		}
		break;
	case AUL_UPDATE_REQUESTED:
		_DBG("[APP %d]     AUL event: AUL_UPDATE_REQUESTED", getpid());
		__invoke_callback((void *)&dummy, APPCORE_BASE_EVENT_UPDATE_REQUESTED);
		break;
	default:
		_DBG("[APP %d]     AUL event: %d", getpid(), type);
		/* do nothing */
		break;
	}

	return 0;
}

EXPORT_API int appcore_base_on_create(void)
{
	int r;

	r = aul_launch_init(__context.ops.receive, NULL);
	if (r < 0) {
		_ERR("Aul init failed: %d", r);
		return -1;
	}

	r = aul_launch_argv_handler(__context.argc, __context.argv);
	if (r < 0) {
		_ERR("Aul argv handler failed: %d", r);
		return -1;
	}

	return 0;
}

EXPORT_API int appcore_base_on_control(bundle *b)
{
	return 0;
}

EXPORT_API int appcore_base_on_terminate()
{
	aul_finalize();

	return 0;
}

EXPORT_API void appcore_base_on_set_event(enum appcore_base_event event)
{
	switch (event) {
	case APPCORE_BASE_EVENT_LOW_BATTERY:
		vconf_notify_key_changed(VCONFKEY_SYSMAN_BATTERY_STATUS_LOW, __on_low_battery, NULL);
		break;
	case APPCORE_BASE_EVENT_DEVICE_ORIENTATION_CHANGED:
		__register_rotation_changed_event();
		break;
	case APPCORE_BASE_EVENT_SUSPENDED_STATE_CHANGE:
		break;

	default:
		break;
	}

}

EXPORT_API void appcore_base_on_unset_event(enum appcore_base_event event)
{
	switch (event) {
	case APPCORE_BASE_EVENT_LOW_BATTERY:
		vconf_ignore_key_changed(VCONFKEY_SYSMAN_BATTERY_STATUS_LOW, __on_low_battery);
		break;
	case APPCORE_BASE_EVENT_DEVICE_ORIENTATION_CHANGED:
		__unregister_rotation_changed_event();
		break;
	case APPCORE_BASE_EVENT_SUSPENDED_STATE_CHANGE:
		break;
	default:
		break;
	}
}

EXPORT_API int appcore_base_on_trim_memory(void)
{
	int (*sqlite3_free_heap_memory)(int);

	sqlite3_free_heap_memory = dlsym(RTLD_DEFAULT,
			"sqlite3_release_memory");
	if (sqlite3_free_heap_memory)
		sqlite3_free_heap_memory(SQLITE_FLUSH_MAX);

	malloc_trim(0);

	return 0;
}

EXPORT_API appcore_base_event_h appcore_base_add_event(enum appcore_base_event event,
		appcore_base_event_cb cb, void *data)
{
	appcore_base_event_node *node;

	if (__context.dirty && !__exist_callback(event)) {
		if (__context.ops.set_event)
			__context.ops.set_event(event, __context.data);
	}

	node = malloc(sizeof(appcore_base_event_node));

	if (node == NULL)
		return NULL;

	node->cb = cb;
	node->type = event;
	node->data = data;
	__events = g_list_append(__events, node);

	return node;
}

EXPORT_API int appcore_base_remove_event(appcore_base_event_h handle)
{
	appcore_base_event_node *node = handle;
	enum appcore_base_event event;

	if (!node || !g_list_find(__events, node))
		return -1;

	event = node->type;
	__events = g_list_remove(__events, node);
	free(node);
	if (__context.dirty && !__exist_callback(event)) {
		if (__context.ops.unset_event)
			__context.ops.unset_event(event, __context.data);
	}

	return 0;
}

EXPORT_API int appcore_base_raise_event(void *event, enum appcore_base_event type)
{
	__invoke_callback(event, type);
	return 0;
}

EXPORT_API int appcore_base_get_rotation_state(enum appcore_base_rm *curr)
{
	if (curr == NULL)
		return -1;

	if (!__rotation.ref)
		return -1;

	*curr = __rotation.rm;
	return 0;
}

EXPORT_API bool appcore_base_is_bg_allowed(void)
{
	return __context.allowed_bg;
}

EXPORT_API bool appcore_base_is_suspended(void)
{
	return __context.suspended_state;
}

EXPORT_API void appcore_base_toggle_suspended_state(void)
{
	__context.suspended_state ^= __context.suspended_state;
}

EXPORT_API void appcore_base_exit(void)
{
	if (__context.ops.exit)
		__context.ops.exit(__context.data);
}

EXPORT_API void appcore_base_add_suspend_timer(void)
{
	__add_suspend_timer();
}

EXPORT_API void appcore_base_remove_suspend_timer(void)
{
	__remove_suspend_timer();
}

static int __on_receive(aul_type type, bundle *b, void *data)
{
	return appcore_base_on_receive(type, b);
}

static int __on_create(void *data)
{
	return appcore_base_on_create();
}

static int __on_control(bundle *b, void *data)
{
	return appcore_base_on_control(b);
}

static int __on_terminate(void *data)
{
	return appcore_base_on_terminate();
}

static int __on_set_i18n(void *data)
{
	return appcore_base_on_set_i18n();
}

static void __on_set_event(enum appcore_base_event event, void *data)
{
	appcore_base_on_set_event(event);
}

static void __on_unset_event(enum appcore_base_event event, void *data)
{
	appcore_base_on_unset_event(event);
}

static void __on_trim_memory(void *data)
{
	appcore_base_on_trim_memory();
}

EXPORT_API appcore_base_ops appcore_base_get_default_ops(void)
{
	appcore_base_ops ops;

	ops.create = __on_create;
	ops.control = __on_control;
	ops.terminate = __on_terminate;
	ops.receive = __on_receive;
	ops.set_i18n = __on_set_i18n;
	ops.init = NULL;
	ops.finish = NULL;
	ops.run = NULL;
	ops.exit = NULL;
	ops.set_event = __on_set_event;
	ops.unset_event = __on_unset_event;
	ops.trim_memory = __on_trim_memory;

	return ops;
}
