/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <iniparser.h>

#include "amd_watchdog_private.h"
#include "amd_watchdog_config.h"

#define CONFIG_PATH "/usr/share/amd/conf/amd_watchdog.conf"
#define CONFIG_SECTION_NAME "Setting"
#define CONFIG_KEY_WATCHDOG "Watchdog"
#define CONFIG_KEY_INTERVAL "WatchdogInterval"
#define CONFIG_KEY_MAX_RETRY_COUNT "WatchdogMaxRetryCount"

struct watchdog_config_s {
	int state;
	unsigned int interval;
	unsigned int max_retry_count;
};

static struct watchdog_config_s __config;

static int __watchdog_config_get_int(dictionary *d,
		const char *section, const char *key)
{
	char buf[512];

	snprintf(buf, sizeof(buf), "%s:%s", section, key);

	return iniparser_getint(d, buf, -1);
}

static const char *__watchdog_config_get_string(dictionary *d,
		const char *section, const char *key)
{
	char buf[512];

	snprintf(buf, sizeof(buf), "%s:%s", section, key);

	return iniparser_getstring(d, buf, NULL);
}

static int __watchdog_config_load(const char *path)
{
	dictionary *d;
	const char *str;
	int r;

	r = access(path, R_OK);
	if (r != 0) {
		_E("Failed to access %s. errno(%d)", path, errno);
		return -1;
	}

	d = iniparser_load(path);
	if (!d) {
		_E("Failed to load %s by iniparser", path);
		return -1;
	}

	str = __watchdog_config_get_string(d, CONFIG_SECTION_NAME,
			CONFIG_KEY_WATCHDOG);
	if (str && !strcmp(str, "enable-by-default"))
		__config.state = WATCHDOG_ENABLE_BY_DEFAULT;
	_W("Operation state: %s", str);

	r = __watchdog_config_get_int(d, CONFIG_SECTION_NAME,
			CONFIG_KEY_INTERVAL);
	if (r > 0) {
		__config.interval = r;
		_W("Interval: %u", __config.interval);
	}

	r = __watchdog_config_get_int(d, CONFIG_SECTION_NAME,
			CONFIG_KEY_MAX_RETRY_COUNT);
	if (r > 0) {
		__config.max_retry_count = r;
		_W("Maximum retry count: %u", __config.max_retry_count);
	}

	iniparser_freedict(d);

	return 0;
}

int _watchdog_config_get_operation_state(void)
{
	return __config.state;
}

unsigned int _watchdog_config_get_interval(void)
{
	return __config.interval;
}

unsigned int _watchdog_config_get_max_retry_count(void)
{
	return __config.max_retry_count;
}

int _watchdog_config_init(void)
{
	_D("Watchdog config init");

	__config.state = WATCHDOG_ENABLE_ON_DEMAND;
	__config.interval = 10000; /* 10 secdons */
	__config.max_retry_count = 1;

	if (__watchdog_config_load(CONFIG_PATH) < 0)
		_W("Failed to load watchdog config");

	return 0;
}

void _watchdog_config_fini(void)
{
	_D("Watchdog config fini");
	__config.state = WATCHDOG_ENABLE_ON_DEMAND;
	__config.interval = 0;
	__config.max_retry_count = 0;
}
