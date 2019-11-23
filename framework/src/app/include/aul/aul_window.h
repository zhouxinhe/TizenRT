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

#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *aul_window_info_h;
typedef void *aul_window_stack_h;

/**
 * @par Description:
 *	This API creates the window stack handle.
 * @par Purpose:
 *      To get information of windows, the stack handle is needed.
 *
 * @param[out]	handle	Handle for the window stack
 * @return	0 if success, negative value(<0) if fail
 *
 * @see
 *	aul_window_stack_del
 * @remark
 *	It should be freed by aul_window_stack_del function.
*/
int aul_window_stack_get(aul_window_stack_h *handle);

/**
 * @par Description:
 *	This API destroy the window stack handle.
 *
 * @param[in]	handle	Handle for the window stack
 * @return	0 if success, negative value(<0) if fail
 *
 * @see
 *	aul_window_stack_get
*/
int aul_window_stack_del(aul_window_stack_h handle);

/**
 * @par Description:
 *	This API invokes iterator function for each window.
 *
 * @param[in]	handle	Handle for the window stack
 * @param[in]	iter_cb	The iteration callback
 * @param[in]	data	The data which will be sent to the iterator
 * @return	0 if success, negative value(<0) if fail
 *
*/
int aul_window_stack_foreach(aul_window_stack_h handle,
		void (*iter_cb)(aul_window_info_h info, void *data), void *data);

/**
 * @par Description:
 *	This API gets the global resource ID from the window handle.
 *
 * @param[in]	info	Handle for the window
 * @param[out]	rid	Global resource ID
 *
 * @return	0 if success, negative value(<0) if fail
 *
*/
int aul_window_stack_info_get_resource_id(aul_window_info_h info, unsigned int *rid);

/**
 * @par Description:
 *	This API gets the process ID from the window handle.
 *
 * @param[in]	info	Handle for the window
 * @param[out]	pid	Process ID
 *
 * @return	0 if success, negative value(<0) if fail
 *
*/
int aul_window_info_get_pid(aul_window_info_h info, int *pid);

/**
 * @par Description:
 *	This API gets the process ID for its parent window from the window handle.
 *
 * @param[in]	info	Handle for the window
 * @param[out]	pid	Process ID
 *
 * @return	0 if success, negative value(<0) if fail
 *
 * @remark
 *	pid will be -1 when the parent window is not exist
 *
*/
int aul_window_info_get_parent_pid(aul_window_info_h info, int *ppid);

/**
 * @par Description:
 *	This API gets the process ID for its ancestor window from the window handle.
 *
 * @param[in]	info	Handle for the window
 * @param[out]	pid	Process ID
 *
 * @return	0 if success, negative value(<0) if fail
 *
 * @remark
 *	pid will be -1 when the ancestor window is not exist
 *
*/
int aul_window_info_get_ancestor_pid(aul_window_info_h info, int *apid);

/**
 * @par Description:
 *	This API gets the window visibility from the window handle.
 *
 * @param[in]	info	Handle for the window
 * @param[out]	visibility	visibility
 *		0	Fully visible state
 *		1	Partially visible state
 *		2	Invisible state by other window
 *		-1	Invisible state
 *
 * @return	0 if success, negative value(<0) if fail
 *
*/
int aul_window_info_get_visibility(aul_window_info_h info, int *visibility);

/**
 * @par Description:
 *	This API gets the flag value of supporting alpha blending.
 *
 * @param[in]	info	Handle for the window
 * @param[out]	alpha	The flag value of supporting alpha blending
 *
 * @return	0 if success, negative value(<0) if fail
 *
*/
int aul_window_info_has_alpha(aul_window_info_h info, bool *alpha);

/**
 * @par Description:
 *	This API gets the flag value of the focused state.
 *
 * @param[in]	info	Handle for the window
 * @param[out]	focused	The flag value of the focused state
 *
 * @return	0 if success, negative value(<0) if fail
 *
*/
int aul_window_info_is_focused(aul_window_info_h info, bool *focused);

typedef enum _aul_window_notification_level_e {
	AUL_WINDOW_NOTIFICATION_LEVEL_NONE = 0,
	AUL_WINDOW_NOTIFICATION_LEVEL_DEFAULT = 10,
	AUL_WINDOW_NOTIFICATION_LEVEL_MEDIUM = 20,
	AUL_WINDOW_NOTIFICATION_LEVEL_HIGH = 30,
	AUL_WINDOW_NOTIFICATION_LEVEL_TOP = 40,
	AUL_WINDOW_NOTIFICATION_LEVEL_PRIVILEGE = 99,
} aul_window_notification_level_e;

/**
 * @par Description:
 *	This API gets the window notification level from the window handle.
 *
 * @param[in]	info	Handle for the window
 * @param[out]	level	Notification level
 * @return	0 if success, negative value(<0) if fail
 *
*/
int aul_window_info_get_notification_level(aul_window_info_h info,
		aul_window_notification_level_e *level);

/**
 * @par Description:
 *	This API gets the location and the size from window handle.
 *
 * @param[in]	info	Handle for the window
 * @param[out]	x	Position x
 * @param[out]	y	Position y
 * @param[out]	w	Width
 * @param[out]	h	Height
 *
 * @return	0 if success, negative value(<0) if fail
 *
*/
int aul_window_info_get_geometry(aul_window_info_h info, int *x, int *y, int *w, int *h);


/**
 * @par Description:
 *	This API gets pid for the focused window.
 *
 * @param[out]	pid	focused pid
 *
 * @return	0 if success, negative value(<0) if fail
 *
*/
int aul_window_get_focused_pid(pid_t *pid);

/*
 * This API is only for Appfw internally.
 */
int aul_window_attach(const char *parent_appid, const char *child_appid);

/*
 * This API is only for Appfw internally.
 */
int aul_window_detach(const char *child_appid);

/**
 * @par Description:
 *      This API gets the flag value of the opaque state.
 *
 * @param[in]   info    Handle for the window
 * @param[out]  opaque  The flag value of the opaque state.
 *
 * @return      0 on success, otherwise a negative error value.
 */
int aul_window_info_get_opaque(aul_window_info_h info, bool *opaque);

#ifdef __cplusplus
}
#endif
