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

#pragma once

#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <glib.h>
#include <pkgmgr-info.h>

#define METADATA_LARGEMEMORY "http://tizen.org/metadata/largememory"
#define METADATA_OOMTERMINATION "http://tizen.org/metadata/oomtermination"
#define METADATA_VIPAPP "http://tizen.org/metadata/vipapp"

typedef struct app_property_s *app_property_h;

int _app_property_add_alias_info(app_property_h app_property,
		const char *alias_appid, const char *appid);
int _app_property_remove_alias_info(app_property_h app_property,
		const char *alias_appid, const char *appid);
const char *_app_property_get_real_appid(app_property_h app_property,
		const char *alias_appid);
GList *_app_property_get_allowed_app_list(app_property_h app_property,
		const char *appid);
app_property_h _app_property_find(uid_t uid);
int _app_property_insert(uid_t uid, const char *appid,
		const pkgmgrinfo_appinfo_h handle);
int _app_property_delete(uid_t uid, const char *appid);
int _app_property_load(uid_t uid);
void _app_property_unload(uid_t uid);
int _app_property_init(void);
void _app_property_fini(void);
void _app_property_cache_invalidate(app_property_h app_property);
bool _app_property_metadata_query_bool(app_property_h app_property,
		const char *appid, const char *key);
int _app_property_metadata_foreach(app_property_h app_property,
		const char *appid, const char *key,
		int (*callback)(const char *value, void *data),
		void *user_data);
bool _app_property_metadata_match(app_property_h app_property,
		const char *appid, const char *key, const char *value);
bool _app_property_metadata_query_activation(app_property_h app_property,
		const char *appid, const char *key);
int _app_property_metadata_add_filter(const char *key, const char *value);
int _app_property_metadata_remove_filter(const char *key, const char *value);
