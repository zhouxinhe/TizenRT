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
#include <unistd.h>
#include <sys/types.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_launchpad.h"

struct launchpad_info {
	int (*launcher)(bundle *, uid_t t, void *);
	void *data;
};

static struct launchpad_info __launchpad;

int _launchpad_set_launcher(int (*callback)(bundle *, uid_t, void *),
		void *user_data)
{
	__launchpad.launcher = callback;
	__launchpad.data = user_data;

	return 0;
}

int _launchpad_launch(bundle *kb, uid_t uid)
{
	if (!__launchpad.launcher) {
		_E("Launcher is not prepared");
		return -1;
	}

	return __launchpad.launcher(kb, uid, __launchpad.data);
}
