/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
 *
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bundle_internal.h>
#include "aul.h"
#include "aul_api.h"
#include "aul_util.h"
#include "aul_sock.h"
#include "launch.h"

API int aul_app_group_get_window(int pid)
{
	int ret;
	bundle *b;
	char buf[128];

	b = bundle_create();
	if (b == NULL) {
		_E("out of memory");
		return -1;
	}

	snprintf(buf, 128, "%d", pid);
	bundle_add_str(b, AUL_K_PID, buf);
	ret = app_send_cmd(AUL_UTIL_PID, APP_GROUP_GET_WINDOW, b);
	bundle_free(b);

	return ret;
}

API int aul_app_group_set_window(int wid)
{
	int ret;
	bundle *b;
	char buf[128];

	b = bundle_create();

	if (b == NULL) {
		_E("out of memory");
		return -1;
	}

	snprintf(buf, 128, "%d", wid);
	bundle_add_str(b, AUL_K_WID, buf);
	ret = app_send_cmd_with_noreply(AUL_UTIL_PID, APP_GROUP_SET_WINDOW, b);
	bundle_free(b);

	return ret;
}

API void aul_app_group_get_leader_pids(int *cnt, int **pids)
{
	int ret;
	int fd;
	app_pkt_t *pkt = NULL;
	int c;

	*cnt = 0;
	*pids = NULL;
	fd = aul_sock_send_raw(AUL_UTIL_PID, getuid(),
			APP_GROUP_GET_LEADER_PIDS, NULL, 0, AUL_SOCK_ASYNC);
	if (fd < 0)
		return;

	ret = aul_sock_recv_reply_pkt(fd, &pkt);
	if (ret < 0 || pkt == NULL)
		return;

	c = pkt->len / sizeof(int);
	if (c > 0 && pkt->len <= AUL_SOCK_MAXBUFF - AUL_PKT_HEADER_SIZE) {
		*pids = malloc(pkt->len);
		if (*pids == NULL) {
			_E("out of memory");
			free(pkt);
			return;
		}

		memcpy(*pids, pkt->data, pkt->len);
		*cnt = c;
	}

	free(pkt);
}

API void aul_app_group_get_group_pids(int leader_pid, int *cnt, int **pids)
{
	int ret;
	int fd;
	app_pkt_t *pkt = NULL;
	bundle *b;
	char buf[128];
	int c;
	*cnt = 0;
	*pids = NULL;

	b = bundle_create();

	if (b == NULL) {
		_E("out of memory");
		return;
	}

	snprintf(buf, 128, "%d", leader_pid);
	bundle_add_str(b, AUL_K_LEADER_PID, buf);

	fd = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			APP_GROUP_GET_GROUP_PIDS, b, AUL_SOCK_ASYNC);

	if (fd > 0) {
		ret = aul_sock_recv_reply_pkt(fd, &pkt);
	} else {
		bundle_free(b);
		return;
	}

	if (ret < 0 || pkt == NULL) {
		bundle_free(b);
		return;
	}

	c = pkt->len / sizeof(int);
	if (c > 0 && pkt->len <= AUL_SOCK_MAXBUFF - AUL_PKT_HEADER_SIZE) {
		*pids = malloc(pkt->len);
		if (*pids == NULL) {
			_E("out of memory");
			goto clear;
		}

		memcpy(*pids, pkt->data, pkt->len);
		*cnt = c;
	}

clear:
	free(pkt);
	bundle_free(b);
}

API int aul_app_group_get_leader_pid(int pid)
{
	int ret;
	bundle *b;
	char buf[128];

	b = bundle_create();

	if (b == NULL) {
		_E("out of memory");
		return -1;
	}

	snprintf(buf, 128, "%d", pid);
	bundle_add_str(b, AUL_K_PID, buf);
	ret = app_send_cmd(AUL_UTIL_PID, APP_GROUP_GET_LEADER_PID, b);
	bundle_free(b);

	return ret;
}

API int aul_app_group_clear_top(void)
{
	unsigned char dummy[1] = { 0 };
	return aul_sock_send_raw(AUL_UTIL_PID, getuid(), APP_GROUP_CLEAR_TOP, dummy, 0, AUL_SOCK_NONE);
}

API int aul_app_group_is_top(void)
{
	int lpid = aul_app_group_get_leader_pid(getpid());

	if (lpid > 0) {
		int cnt;
		int *pids = NULL;
		aul_app_group_get_group_pids(lpid, &cnt, &pids);
		if (cnt > 0) {
			if (pids[cnt-1] == getpid()) {
				free(pids);
				return 1;
			}

			free(pids);
			return 0;
		}
	}

	return 1;
}

API int aul_app_group_get_fg_flag(int pid)
{
	int ret;
	bundle *b;
	char buf[128];

	b = bundle_create();

	if (b == NULL) {
		_E("out of memory");
		return -1;
	}

	snprintf(buf, 128, "%d", pid);
	bundle_add_str(b, AUL_K_PID, buf);
	ret = app_send_cmd(AUL_UTIL_PID, APP_GROUP_GET_FG, b);
	bundle_free(b);

	return ret;
}

API void aul_app_group_lower(int *exit)
{
	int ret;
	unsigned char dummy[1] = { 0 };

	ret = aul_sock_send_raw(AUL_UTIL_PID, getuid(), APP_GROUP_LOWER,
			dummy, 0, AUL_SOCK_NONE);
	if (ret < 0)
		return;
	*exit = ret;
}

API void aul_app_group_get_idle_pids(int *cnt, int **pids)
{
	int ret;
	int fd;
	app_pkt_t *pkt = NULL;
	int c;

	*cnt = 0;
	*pids = NULL;
	fd = aul_sock_send_raw(AUL_UTIL_PID, getuid(),
			APP_GROUP_GET_IDLE_PIDS, NULL, 0, AUL_SOCK_ASYNC);

	if (fd > 0)
		ret = aul_sock_recv_reply_pkt(fd, &pkt);
	else
		return;

	if (pkt == NULL || ret < 0)
		return;

	c = pkt->len / sizeof(int);
	if (c > 0 && pkt->len <= AUL_SOCK_MAXBUFF - AUL_PKT_HEADER_SIZE) {
		*pids = malloc(pkt->len);
		if (*pids == NULL) {
			_E("out of memory");
			free(pkt);
			return;
		}

		memcpy(*pids, pkt->data, pkt->len);
		*cnt = c;
	}

	free(pkt);
}

API int aul_app_group_activate_below(const char *below_appid)
{
	int ret;
	bundle *b;

	if (below_appid == NULL)
		return -1;

	b = bundle_create();

	if (b == NULL) {
		_E("out of memory");
		return -1;
	}

	bundle_add_str(b, AUL_K_APPID, below_appid);
	ret = app_send_cmd(AUL_UTIL_PID, APP_GROUP_ACTIVATE_BELOW, b);
	bundle_free(b);

	return ret;
}

API int aul_app_group_activate_above(const char *above_appid)
{
	int ret;
	bundle *b;

	if (above_appid == NULL)
		return -1;

	b = bundle_create();

	if (b == NULL) {
		_E("out of memory");
		return -1;
	}

	bundle_add_str(b, AUL_K_APPID, above_appid);
	ret = app_send_cmd(AUL_UTIL_PID, APP_GROUP_ACTIVATE_ABOVE, b);
	bundle_free(b);

	return ret;
}


