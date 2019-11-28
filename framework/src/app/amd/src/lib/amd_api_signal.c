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
#include "amd_api_signal.h"
#include "amd_signal.h"

EXPORT_API int amd_signal_send_tep_mount(char *mnt_path[], const char *pkgid)
{
	return _signal_send_tep_mount(mnt_path, pkgid);
}

EXPORT_API int amd_signal_send_tep_unmount(const char *mnt_path)
{
	return _signal_send_tep_unmount(mnt_path);
}

EXPORT_API int amd_signal_send_watchdog(int pid, int signal_num)
{
	return _signal_send_watchdog(pid, signal_num);
}
