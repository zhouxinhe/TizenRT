/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <stdlib.h>
#include <system_info.h>
#include "aul_util.h"

tizen_profile_t _get_tizen_profile(void)
{
	static tizen_profile_t profile = TIZEN_PROFILE_UNKNOWN;
	char *profile_name = NULL;

	if (__builtin_expect(profile != TIZEN_PROFILE_UNKNOWN, 1))
		return profile;

	system_info_get_platform_string("http://tizen.org/feature/profile",
			&profile_name);
	if (profile_name == NULL)
		return profile;

	switch (*profile_name) {
	case 'm':
	case 'M':
		profile = TIZEN_PROFILE_MOBILE;
		break;
	case 'w':
	case 'W':
		profile = TIZEN_PROFILE_WEARABLE;
		break;
	case 't':
	case 'T':
		profile = TIZEN_PROFILE_TV;
		break;
	case 'i':
	case 'I':
		profile = TIZEN_PROFILE_IVI;
		break;
	default: /* common or unknown ==> ALL ARE COMMON. */
		profile = TIZEN_PROFILE_COMMON;
		break;
	}
	free(profile_name);

	return profile;
}
