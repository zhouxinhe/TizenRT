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

#pragma once

#include <bundle.h>

#define NOTI_CONTINUE	0
#define NOTI_STOP	-2

typedef int (*noti_cb)(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data);

int _noti_send(const char *msg, int arg1, int arg2, void *arg3, bundle *data);
int _noti_listen(const char *msg, noti_cb callback);
int _noti_init(void);
void _noti_fini(void);
