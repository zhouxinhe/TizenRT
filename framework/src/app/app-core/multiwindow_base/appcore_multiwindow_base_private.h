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

#pragma once

#define LOG_TAG "APP_CORE_MULTIWINDOW_BASE"

#include <stdio.h>
#include <stdbool.h>
#include <dlog.h>
#include <glib.h>

#include "appcore_base.h"
#include "appcore_multiwindow_base.h"

#ifndef EXPORT_API
#  define EXPORT_API __attribute__ ((visibility("default")))
#endif

#ifndef _DLOG_H_
#  define _ERR(fmt, arg...) \
	do { fprintf(stderr, "appcore: "fmt"\n", ##arg); } while (0)

#  define _INFO(fmt, arg...) \
	do { fprintf(stdout, fmt"\n", ##arg); } while (0)

#  define _DBG(fmt, arg...) \
	do { \
		if (getenv("APPCORE_DEBUG")) { \
			fprintf(stdout,	fmt"\n", ##arg); \
		} \
	} while (0)
#else
#  define _ERR(fmt, arg...) \
	do { \
		fprintf(stderr, "appcore: "fmt"\n", ##arg); \
		LOGE(fmt, ##arg); \
	} while (0)
#  define _INFO(...) LOGI(__VA_ARGS__)
#  define _DBG(...) LOGD(__VA_ARGS__)
#endif

typedef struct _appcore_multiwindow_base_context {
	appcore_multiwindow_base_ops ops;
	void *data;
	int argc;
	char **argv;
	GList *classes;
	GList *instances;

	Ecore_Event_Handler *hshow;
	Ecore_Event_Handler *hhide;
	Ecore_Event_Handler *hvchange;
	Ecore_Event_Handler *hlower;
	Ecore_Event_Handler *hpvchange;
} appcore_multiwindow_base_context;

typedef struct _appcore_multiwindow_base_instance {
	unsigned int window_id;
	char *id;
	void *extra;
	appcore_multiwindow_base_class *shell;
	bool is_resumed;
} appcore_multiwindow_base_instance;

