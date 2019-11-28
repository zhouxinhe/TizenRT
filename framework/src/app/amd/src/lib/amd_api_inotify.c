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

#include "amd_api.h"
#include "amd_api_inotify.h"
#include "amd_inotify.h"

EXPORT_API amd_inotify_watch_info_h amd_inotify_add_watch(const char *path,
		uint32_t mask, amd_inotify_watch_cb callback, void *data)
{
	return _inotify_add_watch(path, mask, callback, data);
}

EXPORT_API void amd_inotify_rm_watch(amd_inotify_watch_info_h handle)
{
	_inotify_rm_watch(handle);
}
