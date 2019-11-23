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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <glib.h>

#include "aul_api.h"
#include "aul_util.h"
#include "aul_sock.h"
#include "aul_error.h"
#include "aul_watchdog.h"
#include "aul.h"

typedef struct watchdog_context_s {
	bool enabled;
} watchdog_context;

static watchdog_context __context;

API int aul_watchdog_enable(void)
{
	int r;

	if (__context.enabled) {
		_W("Watchdog is already enabled");
		return AUL_R_OK;
	}

	r = aul_sock_send_raw(AUL_UTIL_PID, getuid(),
			WATCHDOG_ENABLE, NULL, 0, AUL_SOCK_NONE);
	if (r < 0) {
		_E("Failed to send the watchdog request. ret(%d)", r);
		return aul_error_convert(r);
	}

	__context.enabled = true;
	_D("[__WATCHDOG__] enabled, result(%d)", r);
	return AUL_R_OK;
}

API int aul_watchdog_disable(void)
{
	int r;

	if (!__context.enabled) {
		_W("Watchdog is not enabled");
		return AUL_R_ERROR;
	}

	r = aul_sock_send_raw(AUL_UTIL_PID, getuid(),
			WATCHDOG_DISABLE, NULL, 0, AUL_SOCK_NONE);
	if (r < 0) {
		_E("Failed to send the watchdog request. ret(%d)", r);
		return aul_error_convert(r);
	}

	__context.enabled = false;
	_D("[__WATCHDOG__] disabled, result(%d)", r);
	return AUL_R_OK;
}

API int aul_watchdog_kick(void)
{
	int r;

	if (!__context.enabled) {
		_W("Watchdog is not enabled");
		return AUL_R_ERROR;
	}

	r = aul_sock_send_raw(AUL_UTIL_PID, getuid(),
			WATCHDOG_KICK, NULL, 0, AUL_SOCK_NONE);
	if (r < 0) {
		_E("Failed to send the watchdog request. ret(%d)", r);
		return aul_error_convert(r);
	}

	_D("[__WATCHDOG__] kicked, result(%d)", r);
	return AUL_R_OK;
}
