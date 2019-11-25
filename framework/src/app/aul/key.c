/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <bundle.h>

#include "aul.h"
#include "aul_api.h"
#include "launch.h"

int app_key_event(bundle *kb)
{
	return 0;
}

API int aul_key_init(int (*aul_handler)(bundle *, void *), void *data)
{
	return AUL_R_OK;
}

API int aul_key_reserve()
{
	return AUL_R_OK;
}

API int aul_key_release()
{
	return AUL_R_OK;
}
