/*
 * Copyright (c) 2000 - 2017 Samsung Electronics Co., Ltd. All rights reserved.
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

#include <locale.h>
#include <libintl.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>
#include <glib.h>
#include <vconf.h>

#include "appcore-internal.h"
#include "appcore_base.h"

EXPORT_API int appcore_set_i18n(const char *domainname, const char *dirname)
{
	return appcore_base_set_i18n(domainname, dirname);
}

EXPORT_API int appcore_get_timeformat(enum appcore_time_format *timeformat)
{
	int r;

	if (timeformat == NULL) {
		errno = EINVAL;
		return -1;
	}

	r = vconf_get_int(VCONFKEY_REGIONFORMAT_TIME1224, (int *)timeformat);

	if (r < 0) {
		*timeformat = APPCORE_TIME_FORMAT_UNKNOWN;
		return -1;
	}

	return 0;
}
