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
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "amd_widget_private.h"
#include "amd_widget_logger.h"

#define LOG_PATH "/run/aul/log/amd_widget.log"
#define LOG_MAX_SIZE 131072
#define LOG_MAX_BUF_SIZE 149
#define LOG_MAX_FMT_SIZE 96

struct widget_logger_s {
	int fd;
	int index;
};

static struct widget_logger_s __logger;

int _widget_logger_print(const char *tag, const char *format, ...)
{
	int r;
	int offset;
	time_t c_time;
	char time_buf[32] = { 0, };
	char format_buf[LOG_MAX_FMT_SIZE];
	char buf[LOG_MAX_BUF_SIZE];
	va_list ap;

	if (__logger.fd <= 0) {
		_E("logger is not initialized");
		return -1;
	}

	time(&c_time);
	ctime_r(&c_time, time_buf);

	offset = lseek(__logger.fd, 0, SEEK_CUR);
	if (offset >= LOG_MAX_SIZE)
		lseek(__logger.fd, 0, SEEK_SET);

	va_start(ap, format);
	vsnprintf(format_buf, sizeof(format_buf), format, ap);
	va_end(ap);

	snprintf(buf, sizeof(buf), "[%6d] %-16s %-96s %s",
			__logger.index, tag, format_buf, time_buf);
	r = write(__logger.fd, buf, strlen(buf));
	if (r < 0) {
		_E("Failed to write log message. errno(%d)", errno);
		return -1;
	}

	__logger.index++;
	if (__logger.index < 0)
		__logger.index = 0;

	return 0;
}

int _widget_logger_init(void)
{
	int offset;

	_D("widget logger init");

	__logger.fd = open(LOG_PATH, O_CREAT | O_WRONLY, 0600);
	if (__logger.fd < 0) {
		_E("Failed to open %s. errno(%d)", LOG_PATH, errno);
		return -1;
	}

	offset = lseek(__logger.fd, 0, SEEK_END);
	if (offset >= LOG_MAX_SIZE)
		lseek(__logger.fd, 0, SEEK_SET);

	return 0;
}

void _widget_logger_fini(void)
{
	_D("widget logger fini");

	__logger.index = 0;

	if (__logger.fd > 0) {
		close(__logger.fd);
		__logger.fd = 0;
	}
}
