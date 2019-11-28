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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_proc.h"

int _proc_get_attr(pid_t pid, char *buf, int buf_size)
{
	char path[PATH_MAX];
	int fd;
	ssize_t s;

	if (pid < 1 || !buf) {
		_E("Invalid parameter");
		return -1;
	}

	snprintf(path, sizeof(path), "/proc/%d/attr/current", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		_E("Failed to open %s. errno(%d)", path, errno);
		return -1;
	}

	s = read(fd, buf, buf_size -1);
	if (s <= 0) {
		_E("Failed to read %s. errno(%d)", path, errno);
		close(fd);
		return -1;
	}

	buf[s] = 0;
	close(fd);

	return 0;
}
