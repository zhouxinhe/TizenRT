/*
 * Copyright (c) 2015 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
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

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bundle.h>

#define LAUNCHPAD_PROCESS_POOL_SOCK ".launchpad-process-pool-sock"

#define PAD_CMD_LAUNCH 0
#define PAD_CMD_VISIBILITY 10
#define PAD_CMD_ADD_LOADER 11
#define PAD_CMD_REMOVE_LOADER 12
#define PAD_CMD_MAKE_DEFAULT_SLOTS 13
#define PAD_CMD_DEMAND 14
#define PAD_CMD_PING 15
#define PAD_CMD_UPDATE_APP_TYPE 16

int _create_sock_activation(void);
int _create_server_sock(void);
int _send_cmd_to_launchpad(const char *pad_type, uid_t uid, int cmd,
		bundle *kb);
int _send_cmd_to_launchpad_async(const char *pad_type, uid_t uid, int cmd,
		bundle *kb);
void _send_result_to_client(int fd, int res);
void _send_result_to_client_v2(int fd, int res);
