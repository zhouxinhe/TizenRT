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

#define _GNU_SOURCE

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <malloc.h>
#include <linux/limits.h>
#include <glib.h>
#include <sys/time.h>
#include <dlfcn.h>
#include <vconf.h>
#include <bundle_internal.h>
#include <system_info.h>
#include <gio/gio.h>

#include "appcore-internal.h"
#include "appcore-common.h"
#include "appcore_base.h"

#define SQLITE_FLUSH_MAX		(1024*1024)

static appcore_base_event_h __handles[APPCORE_BASE_EVENT_MAX];
static int __convertor[] = {
	[APPCORE_EVENT_UNKNOWN] = APPCORE_BASE_EVENT_START,
	[APPCORE_EVENT_LOW_MEMORY] = APPCORE_BASE_EVENT_LOW_MEMORY,
	[APPCORE_EVENT_LOW_BATTERY] = APPCORE_BASE_EVENT_LOW_BATTERY,
	[APPCORE_EVENT_LANG_CHANGE] = APPCORE_BASE_EVENT_LANG_CHANGE,
	[APPCORE_EVENT_REGION_CHANGE] = APPCORE_BASE_EVENT_REGION_CHANGE,
	[APPCORE_EVENT_SUSPENDED_STATE_CHANGE] = APPCORE_BASE_EVENT_SUSPENDED_STATE_CHANGE,
	[APPCORE_EVENT_UPDATE_REQUESTED] = APPCORE_BASE_EVENT_UPDATE_REQUESTED,
};

struct appcore_context {
	struct ui_ops ops;
};

static struct appcore_context __context;

EXPORT_API int appcore_set_event_callback(enum appcore_event event,
					  int (*cb) (void *, void *), void *data)
{
	int ret;
	if (__handles[event]) {
		ret = appcore_base_remove_event(__handles[event]);
		if (ret != 0)
			_ERR("Fail to remove event");
	}
	__handles[event] = appcore_base_add_event((enum appcore_base_event)__convertor[event], cb, data);

	return 0;
}

static int __app_create(void *data)
{
	appcore_base_on_create();

	if (__context.ops.cb_app == NULL)
		return -1;

	__context.ops.cb_app(AE_CREATE, __context.ops.data, NULL);
	return 0;
}

static int __app_terminate(void *data)
{
	appcore_base_on_terminate();

	if (__context.ops.cb_app)
		__context.ops.cb_app(AE_TERMINATE, __context.ops.data, NULL);

	return 0;
}

static int __app_control(bundle *b, void *data)
{
	appcore_base_on_control(b);

	if (__context.ops.cb_app)
		__context.ops.cb_app(AE_RESET, __context.ops.data, b);

	return 0;
}

EXPORT_API int appcore_init(const char *name, const struct ui_ops *ops,
			    int argc, char **argv)
{
	appcore_base_ops base_ops = appcore_base_get_default_ops();

	/* override methods */
	base_ops.create = __app_create;
	base_ops.terminate = __app_terminate;
	base_ops.control = __app_control;
	base_ops.run = NULL;
	base_ops.exit = NULL;

	__context.ops = *ops;

	return appcore_base_init(base_ops, argc, argv, NULL);
}

EXPORT_API void appcore_exit(void)
{
	appcore_base_fini();
}

EXPORT_API int appcore_flush_memory(void)
{
	int (*flush_fn) (int);

	_DBG("[APP %d] Flushing memory ...", getpid());
	if (__context.ops.cb_app)
		__context.ops.cb_app(AE_MEM_FLUSH, __context.ops.data, NULL);

	flush_fn = dlsym(RTLD_DEFAULT, "sqlite3_release_memory");
	if (flush_fn)
		flush_fn(SQLITE_FLUSH_MAX);

	malloc_trim(0);
	_DBG("[APP %d] Flushing memory DONE", getpid());

	return 0;
}

