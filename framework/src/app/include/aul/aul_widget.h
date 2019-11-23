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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @par Description:
 *      Widget information handle.
 */
typedef struct aul_widget_info_s *aul_widget_info_h;

/**
 * @par Description:
 *      Called to get the widget information
 * @param[in]   info            The handle of the widget information
 * @param[in]   user_data       The user data passed from the foreach function
 *
 * @pre aul_widget_info_foreach() will invoke this callback.
 * @see aul_widget_info_foreach()
 */
typedef void (*aul_widget_info_cb)(aul_widget_info_h info, void *user_data);

/**
 * @par Description:
 *      Retrieves all widget information of running widget applications.
 * @privlevel   platform
 * @privilege   %http://tizen.org/privilege/internal/default/platform
 * @param[in]   callback        The callback function to invoke
 * @param[in]   user_data       The user data to be passed to the callback function
 * @return      @c 0 on success,
 *              otherwise a negative error value
 * @post This function invokes aul_widget_info_cb() for each widget information.
 * @see aul_widget_info_cb()
 */
int aul_widget_info_foreach(aul_widget_info_cb callback, void *user_data);
int aul_widget_info_foreach_for_uid(aul_widget_info_cb callback,
		void *user_data, uid_t uid);

/**
 * @par Description:
 *      Gets the process ID with the given handle.
 * @param[in]   info            The handle of the widget information
 * @param[out]  pid             The process ID
 * @return      @c 0 on success,
 *              otherwise a negative error value
 */
int aul_widget_info_get_pid(aul_widget_info_h info, pid_t *pid);

/**
 * @par Description:
 *      Gets the surface ID with the given handle.
 * @param[in]   info            The handle of the widget information
 * @param[out]  surf            The surface ID
 * @return      @c 0 on success,
 *              otherwise a negative error value
 */
int aul_widget_info_get_surface_id(aul_widget_info_h info, unsigned int *surf);

/**
 * @par Description:
 *      Gets the widget ID with the given handle.
 * @param[in]   info            The handle of the widget information
 * @param[out]  widget_id       The widget ID
 * @return      @c 0 on success,
 *              otherwise a negative error value
 * @remarks The @a widget_id must be released using free().
 */
int aul_widget_info_get_widget_id(aul_widget_info_h info, char **widget_id);

/**
 * @par Description:
 *      Gets the widget instance ID with the given handle.
 * @param[in]   info            The handle of the widget information
 * @param[out]  instance_id     The widget instance ID
 * @return      @c 0 on success,
 *              otherwise a negative error value
 * @remarks The @a instance_id must be released using free().
 */
int aul_widget_info_get_instance_id(aul_widget_info_h info, char **instance_id);

/**
 * @par Description:
 *      Gets the application ID with the given handle.
 * @param[in]   info            The handle of the widget information
 * @param[out]  app_id          The application ID
 * @return      @c 0 on success,
 *              otherwise a negative error value
 * @remarks The @a app_id must be released using free().
 */
int aul_widget_info_get_app_id(aul_widget_info_h info, char **app_id);

/**
 * @par Description:
 *      Gets the package ID with the given handle.
 * @param[in]   info            The handle of the widget information
 * @param[out]  package_id      The package ID
 * @return      @c 0 on success,
 *              otherwise a negative error value
 * @remarks The @a app_id must be released using free().
 */
int aul_widget_info_get_package_id(aul_widget_info_h info, char **package_id);

/**
 * @par Description:
 *      Gets the path with the given handle.
 * @param[in]   info            The handle of the widget information
 * @param[out]  app_path        The path of the widget application
 * @return      @c 0 on success,
 *              otherwise a negative error value
 * @remarks The @a app_id must be released using free().
 */
int aul_widget_info_get_app_path(aul_widget_info_h info, char **app_path);

/**
 * @par Description:
 *      Change app status.
 * @param[in]   widget_id	The widget app id
 * @param[in]   status		The widget app status
 * @return      @c 0 on success,
 *              otherwise a negative error value
 */
int aul_widget_instance_change_status(const char *widget_id, const char *status);

/**
 * @par Description:
 *      Writes file log.
 * @param[in]   tag		The log tag
 * @param[in]   format		The log foramt
 * @return      @c 0 on success,
 *              otherwise a negative error value
 */
int aul_widget_write_log(const char *tag, const char *format, ...);

#ifdef __cplusplus
}
#endif
