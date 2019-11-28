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

#include "amd_input_private.h"
#include "amd_input_config.h"

#define CONFIG_PATH "/usr/share/amd/conf/amd_input.conf"
#define CONFIG_SECTION_NAME "Setting"
#define CONFIG_KEY_LOCK_TIMEOUT "InputLockTimeout"

struct input_config_s {
	unsigned int interval;
};

static struct input_config_s __config;

static int __input_config_get_int(dictionary *d,
		const char *section, const char *key)
{
	char buf[512];

	snprintf(buf, sizeof(buf), "%s:%s", section, key);

	return iniparser_getint(d, buf, -1);
}

static int __input_config_load(const char *path)
{
	dictionary *d;
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

	r = __input_config_get_int(d, CONFIG_SECTION_NAME,
			CONFIG_KEY_LOCK_TIMEOUT);
	if (r > 0) {
		__config.interval = r;
		_W("Interval: %u", __config.interval);
	}

	iniparser_freedict(d);

	return 0;
}

unsigned int _input_config_get_timeout_interval(void)
{
	return __config.interval;
}

int _input_config_init(void)
{
	_D("Input config init");

	__config.interval = 1000; /* 1 sec */

	if (__input_config_load(CONFIG_PATH) < 0)
		_W("Failed to load input config");

	return 0;
}

void _input_config_fini(void)
{
	_D("Input config fini");
	__config.interval = 0;
}
