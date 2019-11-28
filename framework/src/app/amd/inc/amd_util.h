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

#include <unistd.h>
#include <dlog.h>
#include <glib.h>
#include <stdbool.h>
#include <tzplatform_config.h>

#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "AMD"

#define _E(fmt, arg...) LOGE(fmt, ##arg)
#define _D(fmt, arg...) LOGD(fmt, ##arg)
#define _W(fmt, arg...) LOGW(fmt, ##arg)
#define _I(fmt, arg...) LOGI(fmt, ##arg)

#define MAX_LOCAL_BUFSZ 128
#define MAX_PID_STR_BUFSZ 20
#define MAX_UID_STR_BUFSZ 20

#define MAX_PACKAGE_STR_SIZE 512
#define MAX_PACKAGE_APP_PATH_SIZE 512

#define REGULAR_UID_MIN 5000

#define GSLIST_FOREACH_SAFE(list, l, l_next)			\
	for (l = list, l_next = g_slist_next(l);		\
			l;					\
			l = l_next, l_next = g_slist_next(l))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

int _util_save_log(const char *tag, const char *message);
int _util_init(void);
void _util_fini(void);
bool _util_check_oom(void);
