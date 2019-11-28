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

#include <glib.h>

typedef GList *app_group_h;

app_group_h _app_group_find(int pid);
int _app_group_get_window(app_group_h h);
void _app_group_get_group_pids(int leader_pid, int *cnt, int **pids);
int _app_group_get_leader_pid(app_group_h h);
int _app_group_init(void);
void _app_group_fini(void);
