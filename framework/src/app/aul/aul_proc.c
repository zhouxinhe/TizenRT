/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>

#include "aul_api.h"
#include "aul_proc.h"
#include "aul_util.h"

#define MAX_CMD_BUFSZ 1024

API uid_t aul_proc_get_usr_bypid(int pid)
{
	char buf[MAX_CMD_BUFSZ];
	int ret;
	uid_t uid;
	struct stat DirStat;

	snprintf(buf, sizeof(buf), "/proc/%d", pid);
	ret = stat(buf, &DirStat);
	if (ret < 0)
		uid = (uid_t)-1;
	else
		uid = DirStat.st_uid;

	return uid;
}

