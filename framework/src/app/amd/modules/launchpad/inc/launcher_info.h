/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd All Rights Reserved
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
 */

#ifndef __LAUNCHER_INFO_H__
#define __LAUNCHER_INFO_H__

#include <glib.h>

typedef struct launcher_info_s *launcher_info_h;

GList *_launcher_info_load(const char *path);
void _launcher_info_unload(GList *info);
launcher_info_h _launcher_info_find(GList *info_list, const char *app_type);
const char *_launcher_info_get_exe(launcher_info_h launcher_info);
GList *_launcher_info_get_extra_args(launcher_info_h launcher_info);

#endif /* __LAUNCHER_INFO_H__ */
