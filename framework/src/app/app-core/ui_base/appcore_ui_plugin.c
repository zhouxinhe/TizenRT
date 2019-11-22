/*
 * Copyright (c) 2017 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <unistd.h>
#include <dlfcn.h>
#include <dlog.h>

#include "appcore_ui_plugin.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "APP_CORE_UI_PLUGIN"

#define PATH_LIBAPPCORE_UI_PLUGIN \
	"/usr/share/appcore/plugins/libappcore-ui-plugin.so"
#define APPCORE_UI_PLUGIN_INIT "APPCORE_UI_PLUGIN_INIT"
#define APPCORE_UI_PLUGIN_FINI "APPCORE_UI_PLUGIN_FINI"

static int (*__plugin_init)(appcore_ui_base_ops *ops, int argc, char **argv,
		unsigned int *hint);
static int (*__plugin_fini)(void);
static void *__handle;

static void __unload_appcore_ui_plugin(void)
{
	if (__handle) {
		dlclose(__handle);
		__handle = NULL;
	}

	__plugin_init = NULL;
	__plugin_fini = NULL;
}

static void __load_appcore_ui_plugin(void)
{
	if (access(PATH_LIBAPPCORE_UI_PLUGIN, F_OK) != 0)
		return;

	if (!__handle) {
		__handle = dlopen(PATH_LIBAPPCORE_UI_PLUGIN, RTLD_LAZY);
		if (!__handle) {
			LOGE("Failed to open %s", PATH_LIBAPPCORE_UI_PLUGIN);
			return;
		}
	}

	__plugin_init = dlsym(__handle, APPCORE_UI_PLUGIN_INIT);
	if (!__plugin_init)
		LOGW("Failed to load %s symbol", APPCORE_UI_PLUGIN_INIT);

	__plugin_fini = dlsym(__handle, APPCORE_UI_PLUGIN_FINI);
	if (!__plugin_fini)
		LOGW("Failed to load %s symbol", APPCORE_UI_PLUGIN_FINI);
}

void appcore_ui_plugin_init(appcore_ui_base_ops *ops, int argc, char **argv,
		unsigned int *hint)
{
	LOGI("[PLUGIN] init");

	if (!__plugin_init && !__plugin_fini)
		__load_appcore_ui_plugin();

	if (__plugin_init)
		__plugin_init(ops, argc, argv, hint);
}

void appcore_ui_plugin_fini(void)
{
	LOGI("[PLUGIN] fini");

	if (__plugin_fini)
		__plugin_fini();

	__unload_appcore_ui_plugin();
}
