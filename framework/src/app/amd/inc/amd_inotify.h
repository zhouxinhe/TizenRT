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

#include <stdbool.h>
#include <sys/inotify.h>

typedef struct inotify_watch_info_s *inotify_watch_info_h;

typedef bool (*inotify_watch_cb)(const char *event_name, void *data);

inotify_watch_info_h _inotify_add_watch(const char *path, uint32_t mask,
		inotify_watch_cb callback, void *data);
void _inotify_rm_watch(inotify_watch_info_h handle);
int _inotify_init(void);
void _inotify_fini(void);
