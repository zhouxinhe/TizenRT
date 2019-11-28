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
#include <stdlib.h>
#include <system_info.h>
#include <iniparser.h>

#include "amd_config.h"
#include "amd_util.h"

#define CONFIG_FILE_PATH "/usr/share/amd/conf/amd.conf"
#define CONFIG_SECTION_NAME "configuration"
#define CONFIG_SERVICE_APP_ONBOOT_INTERVAL "service_app_onboot_interval"
#define CONFIG_FG_TIMEOUT "fg_timeout"

typedef struct config_s {
	tizen_profile_t profile;
	unsigned int onboot_interval;
	unsigned int fg_timeout;
} config;

static config __config;

tizen_profile_t _config_get_tizen_profile(void)
{
	char *profile_name = NULL;

	if (__builtin_expect(__config.profile != TIZEN_PROFILE_UNKNOWN, 1))
		return __config.profile;

	system_info_get_platform_string("http://tizen.org/feature/profile",
			&profile_name);
	if (profile_name == NULL)
		return __config.profile;

	switch (*profile_name) {
	case 'm':
	case 'M':
		__config.profile = TIZEN_PROFILE_MOBILE;
		break;
	case 'w':
	case 'W':
		__config.profile = TIZEN_PROFILE_WEARABLE;
		break;
	case 't':
	case 'T':
		__config.profile = TIZEN_PROFILE_TV;
		break;
	case 'i':
	case 'I':
		__config.profile = TIZEN_PROFILE_IVI;
		break;
	default: /* common or unknown ==> ALL ARE COMMON. */
		__config.profile = TIZEN_PROFILE_COMMON;
		break;
	}
	free(profile_name);

	return __config.profile;
}

unsigned int _config_get_onboot_interval(void)
{
	return __config.onboot_interval;
}

unsigned int _config_get_fg_timeout(void)
{
	return __config.fg_timeout;
}

static int __get_config_int(dictionary *d, const char *key)
{
	char buf[512];
	int val;

	snprintf(buf, sizeof(buf), "configuration:%s", key);
	val = iniparser_getint(d, buf, -1);
	if (val < 0) {
		_W("Failed to get %s", buf);
		return -1;
	}

	return val;
}

static int __load_config_file(const char *path)
{
	int r;
	dictionary *d;

	r = access(path, F_OK);
	if (r != 0) {
		_W("Failed to access %s, errno(%d)", path, errno);
		return -1;
	}

	d = iniparser_load(path);
	if (!d) {
		_E("Failed to load %s", path);
		return -1;
	}

	r = __get_config_int(d, CONFIG_SERVICE_APP_ONBOOT_INTERVAL);
	if (r > 0) {
		__config.onboot_interval = r;
		_I("[__CONFIG__] Onboot interval: %u",
				__config.onboot_interval);
	}

	r = __get_config_int(d, CONFIG_FG_TIMEOUT);
	if (r > 0) {
		__config.fg_timeout = r;
		_I("[__CONFIG__] FG timeout: %u", __config.fg_timeout);
	}

	iniparser_freedict(d);

	return 0;
}

int _config_init(void)
{
	_D("config init");

	__config.profile = TIZEN_PROFILE_UNKNOWN;
	__config.onboot_interval = 3000;
	__config.fg_timeout = 5000;

	if (__load_config_file(CONFIG_FILE_PATH) < 0)
		_W("Failed to load config file");

	return 0;
}

void _config_fini(void)
{
	_D("config fini");
}
