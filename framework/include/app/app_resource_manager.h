/*
 * Copyright (c) 2011 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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

#ifndef __TIZEN_APPFW_RESOURCE_MANAGER_H__
#define __TIZEN_APPFW_RESOURCE_MANAGER_H__

#include <tizen.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file app_resource_manager.h
 */

/**
 * @addtogroup CAPI_RESOURCE_MANAGER_MODULE
 * @{
 */

/**
 * @brief Enumeration for Resource Types
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
typedef enum {
	APP_RESOURCE_TYPE_IMAGE = 0, /**<Image*/
	APP_RESOURCE_TYPE_LAYOUT, /**<Edje*/
	APP_RESOURCE_TYPE_SOUND, /**<Sound*/
	APP_RESOURCE_TYPE_BIN, /**<Bin*/
	APP_RESOURCE_TYPE_MIN = APP_RESOURCE_TYPE_IMAGE,
	APP_RESOURCE_TYPE_MAX = APP_RESOURCE_TYPE_BIN,
/*add values between APP_RESOURCE_TYPE_MIN and APP_RESOURCE_TYPE_MAX*/
} app_resource_e;


/**
 * @brief Enumeration for App Resource Manager Error.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
typedef enum {
	APP_RESOURCE_ERROR_NONE = TIZEN_ERROR_NONE, /**< Successful */
	APP_RESOURCE_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER, /**< Invalid parameter */
	APP_RESOURCE_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY, /**< Out of memory */
	APP_RESOURCE_ERROR_IO_ERROR = TIZEN_ERROR_IO_ERROR, /**< I/O error */
} app_resource_error_e;


/**
 * @brief Creates resource manager and get from db.
 *
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks If resource manager already exists,
 *			It will just return APP_RESOURCE_ERROR_NONE
 * @return @c 0 on success,
 *         otherwise a negative error value
 * @retval #APP_RESOURCE_ERROR_NONE Successful
 * @retval #APP_RESOURCE_ERROR_IO_ERROR IO Internal I/O Error
 * @retval #APP_RESOURCE_ERROR_OUT_OF_MEMORY Out of memory
 * @see	app_resource_manager_release()
 */
int app_resource_manager_init(void);


/**
 * @brief Converts resource ID to path name
 *
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks If resource manager is not created yet,
 *			app_resource_manager_init() will be invoked automatically.
 *			Caller should free the returned pointer.
 * @param[in] type Resource type @see app_resource_e
 * @param[in] id Resource ID
 * @param[out] path The name of requested resource on success, otherwise NULL
 * @return @c 0 on success,
 *         otherwise a negative error value
 * @retval #APP_RESOURCE_ERROR_NONE Successful
 * @retval #APP_RESOURCE_ERROR_INVALID_PARAMETER Invalid Parameter
 * @retval #APP_RESOURCE_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #APP_RESOURCE_ERROR_IO_ERROR Internal I/O Error or failed to find valid resource
 * @see	app_resource_manager_init()
 */
int app_resource_manager_get(app_resource_e type, const char *id, char **path);


/**
 * @brief Destroys resource manager.
 *
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks Please note that the instance of resource manager should only be released when the application is closing.
 *          It is a highly recommended way to improve run-time performance.
 * @return @c 0 on success,
 *         otherwise a negative error value
 * @retval #APP_RESOURCE_ERROR_NONE Successful
 * @see	app_resource_manager_init()
 */
int app_resource_manager_release(void);


/**
 * @}
 */


#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_APPFW_RESOURCE_MANAGER_H__ */

