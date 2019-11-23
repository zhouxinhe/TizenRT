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
 */

#define _GNU_SOURCE
#include <errno.h>

#include "aul_util.h"
#include "aul_error.h"
#include "aul_sock.h"
#include "aul.h"

int aul_error_convert(int res)
{
	int ret;

	switch (res) {
	case -EREJECTED:
		ret = AUL_R_EREJECTED;
		break;
	case -ENOENT:
		ret = AUL_R_ENOAPP;
		break;
	case -ETERMINATING:
		ret = AUL_R_ETERMINATING;
		break;
	case -EILLEGALACCESS:
		ret = AUL_R_EILLACC;
		break;
	case -ELOCALLAUNCH_ID:
		ret = AUL_R_LOCAL;
		break;
	case -EAGAIN:
		ret = AUL_R_ETIMEOUT;
		break;
	case -EINVAL:
		ret = AUL_R_EINVAL;
		break;
	case -ECOMM:
		ret = AUL_R_ECOMM;
		break;
	case -ECANCELED:
		ret = AUL_R_ECANCELED;
		break;
	default:
		ret = AUL_R_ERROR;
		break;
	}

	return ret;
}

