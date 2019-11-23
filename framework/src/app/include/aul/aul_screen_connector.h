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

#ifndef __AUL_SCREEN_CONNECTOR_H__
#define __AUL_SCREEN_CONNECTOR_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	AUL_SCREEN_TYPE_WIDGET = 0x01,
	AUL_SCREEN_TYPE_WATCH = 0x02,
	AUL_SCREEN_TYPE_UI = 0x04,
	AUL_SCREEN_TYPE_ALL = AUL_SCREEN_TYPE_WIDGET | AUL_SCREEN_TYPE_WATCH | AUL_SCREEN_TYPE_UI,
} aul_screen_type_e;

typedef enum {
	AUL_SCREEN_CONNECTOR_EVENT_TYPE_ADD,
	AUL_SCREEN_CONNECTOR_EVENT_TYPE_REMOVE,
	AUL_SCREEN_CONNECTOR_EVENT_TYPE_UPDATE,
} aul_screen_connector_event_type_e;

typedef enum {
	AUL_SCREEN_STATUS_RESUME,
	AUL_SCREEN_STATUS_PRE_RESUME,
	AUL_SCREEN_STATUS_PAUSE,
} aul_screen_status_e;

typedef void (*aul_screen_viewer_cb)(const char *appid,
		const char *instance_id, const int pid,
		const unsigned int surface_id,
		aul_screen_connector_event_type_e event_type, void *data);

typedef struct aul_screen_viewer_s *aul_screen_viewer_h;

/*
 * This API is only for Appfw internally.
 */
int aul_screen_connector_add_app_screen(const char *instance_id,
		unsigned int surf);

/*
 * This API is only for Appfw internally.
 */
int aul_screen_connector_remove_app_screen(const char *instance_id);

/*
 * This API is only for Appfw internally.
 */
int aul_screen_connector_send_update_request(const char *appid,
		const char *instance_id);

/*
 * This API is only for Appfw internally.
 */
int aul_screen_connector_add_screen_viewer(aul_screen_viewer_cb callback,
		aul_screen_type_e type, bool priv,
		void *data, aul_screen_viewer_h *handle);

/*
 * This API is only for Appfw internally.
 */
int aul_screen_connector_remove_screen_viewer(aul_screen_viewer_h handle);

/*
 * This API is only for Appfw internally.
 */
int aul_screen_connector_get_appid_by_surface_id(unsigned int surface_id,
		char **appid);

/*
 * This API is only for Appfw internally.
 */
int aul_screen_connector_get_instance_id_by_surface_id(unsigned int surface_id,
		char **instance_id);

/*
 * This API is only for Appfw internally.
 */
int aul_screen_connector_update_screen_viewer_status(aul_screen_status_e status,
		unsigned int provider_surf);

#ifdef __cplusplus
}
#endif

#endif /* __AUL_SCREEN_CONNECTOR_H__ */
