/*
 * Copyright (c) 2017 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <stdlib.h>

#include <glib.h>
#include <glib-object.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <bundle.h>
#include <bundle_internal.h>
#include <aul.h>
#include <aul_app_com.h>
#include <dlog.h>
#include <appcore_multiwindow_base.h>

#include "widget_app.h"
#include "widget-log.h"
#include "widget-private.h"
#include "widget_app_internal.h"
#include "widget-private.h"
#include "widget_base.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "CAPI_WIDGET_APPLICATION"
static char *__class_id;

/* LCOV_EXCL_START */
static void __inst_cb(const char *class_id, const char *id,
		appcore_multiwindow_base_instance_h cxt, void *data)
{
	if (!__class_id)
		__class_id = strdup(class_id);
}
/* LCOV_EXCL_STOP */

EXPORT_API int widget_app_restart(void)
{
	int ret;
	int status = AUL_WIDGET_INSTANCE_EVENT_APP_RESTART_REQUEST;
	bundle *kb;

	appcore_multiwindow_base_instance_foreach_full(__inst_cb, NULL);

	kb = bundle_create();
	bundle_add_str(kb, AUL_K_WIDGET_ID, __class_id);
	bundle_add_byte(kb, AUL_K_WIDGET_STATUS, &status, sizeof(int));
	ret = aul_app_com_send(widget_base_get_viewer_endpoint(), kb);
	bundle_free(kb);
	if (__class_id) {
		free(__class_id);
		__class_id = NULL;
	}

	if (ret != AUL_R_OK) {
		_E("failed to kill app");
		return WIDGET_ERROR_IO_ERROR;
	}
	return WIDGET_ERROR_NONE;
}

