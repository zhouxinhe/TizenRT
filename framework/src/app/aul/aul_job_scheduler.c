/*
 * Copyright (c) 2017 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <glib.h>
#include <bundle_internal.h>

#include "aul_util.h"
#include "aul_api.h"
#include "aul_sock.h"
#include "aul.h"
#include "aul_job_scheduler.h"

API int aul_job_scheduler_update_job_status(const char *job_id,
		aul_job_status_e job_status)
{
	char buf[12];
	bundle *b;
	int r;

	if (job_id == NULL || job_status > JOB_STATUS_FINISHED) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	b = bundle_create();
	if (b == NULL) {
		_E("Out of memory");
		return AUL_R_ERROR;
	}

	r = bundle_add(b, AUL_K_JOB_ID, job_id);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add job(%s)", job_id);
		bundle_free(b);
		return AUL_R_ERROR;
	}

	snprintf(buf, sizeof(buf), "%u", job_status);
	r = bundle_add(b, AUL_K_JOB_STATUS, buf);
	if (r != BUNDLE_ERROR_NONE) {
		_E("Failed to add job status(%u)", job_status);
		bundle_free(b);
		return AUL_R_ERROR;
	}

	r = aul_sock_send_bundle(AUL_UTIL_PID, getuid(), JOB_STATUS_UPDATE,
			b, AUL_SOCK_NOREPLY);
	if (r != 0) {
		_E("Failed to update job status(%s:%u)", job_id, job_status);
		bundle_free(b);
		return r;
	}
	bundle_free(b);

	return AUL_R_OK;
}
