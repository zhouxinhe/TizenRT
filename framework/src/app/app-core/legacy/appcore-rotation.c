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

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <sensor_internal.h>
#include <vconf.h>
#include "appcore-internal.h"

struct rot_s {
	int handle;
	int (*callback) (void *event_info, enum appcore_rm, void *);
	enum appcore_rm mode;
	int lock;
	void *cbdata;
	int cb_set;
	int sensord_started;

	struct ui_wm_rotate* wm_rotate;
};
static struct rot_s rot;

struct rot_evt {
	enum auto_rotation_state re;
	enum appcore_rm rm;
};

static struct rot_evt re_to_rm[] = {
	{
		AUTO_ROTATION_DEGREE_0,
		APPCORE_RM_PORTRAIT_NORMAL,
	},
	{
		AUTO_ROTATION_DEGREE_90,
		APPCORE_RM_LANDSCAPE_NORMAL,
	},
	{
		AUTO_ROTATION_DEGREE_180,
		APPCORE_RM_PORTRAIT_REVERSE,
	},
	{
		AUTO_ROTATION_DEGREE_270,
		APPCORE_RM_LANDSCAPE_REVERSE,
	},
};

static enum appcore_rm __get_mode(sensor_data_t data)
{
	int i;
	int event;
	enum appcore_rm m;

	m = APPCORE_RM_UNKNOWN;
	if (data.value_count > 0) {
		event = (int)data.values[0];
	} else {
		_ERR("Failed to get sensor data");
		return -1;
	}

	for (i = 0; i < sizeof(re_to_rm) / sizeof(re_to_rm[0]); i++) {
		if (re_to_rm[i].re == event) {
			m = re_to_rm[i].rm;
			break;
		}
	}

	return m;
}

static void __changed_cb(sensor_t sensor, unsigned int event_type,
		sensor_data_t *data, void *user_data)
{
	enum appcore_rm m;

	if (rot.lock)
		return;

	if (event_type != AUTO_ROTATION_CHANGE_STATE_EVENT) {
		errno = EINVAL;
		return;
	}

	m = __get_mode(*data);

	_DBG("[APP %d] Rotation: %d -> %d", getpid(), rot.mode, m);

	if (rot.callback) {
		if (rot.cb_set && rot.mode != m) {
			_DBG("[APP %d] Rotation: %d -> %d", getpid(), rot.mode, m);
			rot.callback((void *)&m, m, user_data);
			rot.mode = m;
		}
	}
}

static void __lock_cb(keynode_t *node, void *data)
{
	int r;
	enum appcore_rm m;

	rot.lock = !vconf_keynode_get_bool(node);

	if (rot.lock) {
		m = APPCORE_RM_PORTRAIT_NORMAL;
		if (rot.mode != m) {
			rot.callback((void *)&m, m, data);
			rot.mode = m;
		}
		_DBG("[APP %d] Rotation locked", getpid());
		return;
	}

	_DBG("[APP %d] Rotation unlocked", getpid());
	if (rot.callback) {
		if (rot.cb_set) {
			r = appcore_get_rotation_state(&m);
			_DBG("[APP %d] Rotmode prev %d -> curr %d", getpid(),
			     rot.mode, m);
			if (!r && rot.mode != m) {
				rot.callback((void *)&m, m, data);
				rot.mode = m;
			}
		}
	}
}

static void __add_rotlock(void *data)
{
	int r;
	int lock;

	lock = 0;
	r = vconf_get_bool(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL, &lock);
	if (r)
		_DBG("[APP %d] Rotation vconf get bool failed", getpid());

	rot.lock = !lock;

	vconf_notify_key_changed(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL, __lock_cb,
				 data);
}

static void __del_rotlock(void)
{
	vconf_ignore_key_changed(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL, __lock_cb);
	rot.lock = 0;
}

EXPORT_API int appcore_set_rotation_cb(int (*cb) (void *evnet_info, enum appcore_rm, void *),
				       void *data)
{
	if (rot.wm_rotate)
		return rot.wm_rotate->set_rotation_cb(cb, data);
	else {
		bool r;
		int handle;
		sensor_t sensor = sensord_get_sensor(AUTO_ROTATION_SENSOR);

		if (cb == NULL) {
			errno = EINVAL;
			return -1;
		}

		if (rot.callback != NULL) {
			errno = EALREADY;
			return -1;
		}

		handle = sensord_connect(sensor);
		if (handle < 0) {
			_ERR("sensord_connect failed: %d", handle);
			return -1;
		}

		r = sensord_register_event(handle, AUTO_ROTATION_CHANGE_STATE_EVENT,
				      SENSOR_INTERVAL_NORMAL, 0, __changed_cb, data);
		if (!r) {
			_ERR("sensord_register_event failed");
			sensord_disconnect(handle);
			return -1;
		}

		rot.cb_set = 1;
		rot.callback = cb;
		rot.cbdata = data;

		r = sensord_start(handle, 0);
		if (!r) {
			_ERR("sensord_start failed");
			r = sensord_unregister_event(handle, AUTO_ROTATION_CHANGE_STATE_EVENT);
			if (!r)
				_ERR("sensord_unregister_event failed");

			rot.callback = NULL;
			rot.cbdata = NULL;
			rot.cb_set = 0;
			rot.sensord_started = 0;
			sensord_disconnect(handle);
			return -1;
		}
		rot.sensord_started = 1;

		rot.handle = handle;
		__add_rotlock(data);
	}
	return 0;
}

EXPORT_API int appcore_unset_rotation_cb(void)
{
	if (rot.wm_rotate)
		return rot.wm_rotate->unset_rotation_cb();
	else {
		bool r;

		_retv_if(rot.callback == NULL, 0);

		__del_rotlock();

		if (rot.cb_set) {
			r = sensord_unregister_event(rot.handle,
						AUTO_ROTATION_CHANGE_STATE_EVENT);
			if (!r) {
				_ERR("sensord_unregister_event failed");
				return -1;
			}
			rot.cb_set = 0;
		}
		rot.callback = NULL;
		rot.cbdata = NULL;

		if (rot.sensord_started == 1) {
			r = sensord_stop(rot.handle);
			if (!r) {
				_ERR("sensord_stop failed");
				return -1;
			}
			rot.sensord_started = 0;
		}

		r = sensord_disconnect(rot.handle);
		if (!r) {
			_ERR("sensord_disconnect failed");
			return -1;
		}
		rot.handle = -1;
	}
	return 0;
}

EXPORT_API int appcore_get_rotation_state(enum appcore_rm *curr)
{
	if (rot.wm_rotate)
		return rot.wm_rotate->get_rotation_state(curr);
	else {
		bool r;
		sensor_data_t data;

		if (curr == NULL) {
			errno = EINVAL;
			return -1;
		}

		r = sensord_get_data(rot.handle, AUTO_ROTATION_SENSOR, &data);
		if (!r) {
			_ERR("sensord_get_data failed");
			*curr = APPCORE_RM_UNKNOWN;
			return -1;
		}

		*curr = __get_mode(data);
	}
	return 0;
}


