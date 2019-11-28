/*
 * Copyright (c) 2016 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE

#include <stdbool.h>
#include <malloc.h>
#include <sys/mman.h>

#include <glib.h>
#include <wayland-client.h>
#include <tizen-extension-client-protocol.h>
#include <xkbcommon/xkbcommon.h>
#include <aul.h>
#include <amd.h>

#include "amd_input_private.h"
#include "amd_input_config.h"

static bool locked;
static bool init_done;
static guint timer;
static unsigned int timeout_val;
static int latest_pid;
static struct tizen_keyrouter *keyrouter;
static struct tizen_input_device_manager *input_devmgr;
static struct wl_display *display;
static struct wl_seat *seat;
static guint sid;

struct xkb_context *g_ctx;
struct xkb_keymap *g_keymap;
struct wl_keyboard *keyboard;
static uint32_t keyrouter_id;
static uint32_t input_devmgr_id;
static uint32_t seat_id;

typedef struct _keycode_map {
	xkb_keysym_t keysym;
	xkb_keycode_t *keycodes;
	int nkeycodes;
} keycode_map;

static int __input_lock(void);
static int __input_unlock(void);

#define TIZEN_FEATURE_BLOCK_INPUT \
	(!(amd_config_get_tizen_profile() & \
	   (AMD_TIZEN_PROFILE_TV | AMD_TIZEN_PROFILE_IVI)))

static void __keyboard_keymap(void *data, struct wl_keyboard *keyboard,
		uint32_t format, int fd, uint32_t size)
{
	char *map = NULL;

	LOGD("format=%d, fd=%d, size=%d", format, fd, size);
	if (!g_ctx) {
		LOGE("This client failed to make xkb context");
		close(fd);
		return;
	}

	if (format != WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1) {
		LOGE("Invaild format: %d", format);
		close(fd);
		return;
	}

	map = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		LOGE("Failed to mmap from fd(%d) size(%d)", fd, size);
		close(fd);
		return;
	}

	if (g_keymap)
		xkb_map_unref(g_keymap);

	g_keymap = xkb_map_new_from_string(g_ctx, map,
			XKB_KEYMAP_FORMAT_TEXT_V1, 0);
	munmap(map, size);
	if (!g_keymap)
		LOGE("Failed to get keymap from fd(%d)", fd);
	close(fd);
}

static void __keyboard_enter(void *data, struct wl_keyboard *keyboard,
		uint32_t serial, struct wl_surface *surface,
		struct wl_array *keys)
{
	LOGD("serial=%d", serial);
}

static void __keyboard_leave(void *data, struct wl_keyboard *keyboard,
		uint32_t serial, struct wl_surface *surface)
{
	LOGD("serial=%d", serial);
}

static void __keyboard_key(void *data, struct wl_keyboard *keyboard,
		uint32_t serial, uint32_t time, uint32_t key, uint32_t state_w)
{
	LOGD("serial=%d, time=%d, key=%d, state_w=%d",
			serial, time, key, state_w);
}

static void __keyboard_modifiers(void *data, struct wl_keyboard *keyboard,
		uint32_t serial, uint32_t mods_depressed, uint32_t mods_latched,
		uint32_t mods_locked, uint32_t group)
{
	LOGD("serial=%d, mods_depressed=%d, mods_latched=%d mods_locked=%d, " \
			"group=%d", serial, mods_depressed, mods_latched,
			mods_locked, group);
}

static const struct wl_keyboard_listener keyboard_listener = {
	.keymap = __keyboard_keymap,
	.enter = __keyboard_enter,
	.leave = __keyboard_leave,
	.key = __keyboard_key,
	.modifiers = __keyboard_modifiers
};

static gboolean __timeout_handler(void *data)
{
	timer = 0;
	__input_unlock();
	return FALSE;
}

static void __find_keycode(struct xkb_keymap *keymap, xkb_keycode_t key,
		void *data)
{
	keycode_map *found_keycodes = (keycode_map *)data;
	xkb_keysym_t keysym = found_keycodes->keysym;
	int nsyms = 0;
	const xkb_keysym_t *syms_out = NULL;
	xkb_keycode_t *keycodes;

	nsyms = xkb_keymap_key_get_syms_by_level(keymap, key, 0, 0, &syms_out);
	if (nsyms && syms_out && *syms_out == keysym) {
		found_keycodes->nkeycodes++;
		keycodes = realloc(found_keycodes->keycodes,
				sizeof(int) * found_keycodes->nkeycodes);
		if (keycodes == NULL) {
			LOGE("Failed to reallocate the keycodes");
			found_keycodes->nkeycodes--;
			return;
		}
		found_keycodes->keycodes = keycodes;
		found_keycodes->keycodes[found_keycodes->nkeycodes - 1] = key;
	}
}

static int __xkb_keycode_from_keysym(struct xkb_keymap *keymap,
		xkb_keysym_t keysym, xkb_keycode_t **keycodes)
{
	keycode_map found_keycodes = {0,};

	found_keycodes.keysym = keysym;
	xkb_keymap_key_for_each(g_keymap, __find_keycode, &found_keycodes);
	*keycodes = found_keycodes.keycodes;

	return found_keycodes.nkeycodes;
}

static void __keygrab_request(struct tizen_keyrouter *tizen_keyrouter,
		struct wl_surface *surface, uint32_t key, uint32_t mode)
{
	tizen_keyrouter_set_keygrab(tizen_keyrouter, surface, key, mode);
	LOGD("request set_keygrab (key:%d, mode:%d)!", key, mode);
}

static void __keyungrab_request(struct tizen_keyrouter *tizen_keyrouter,
		struct wl_surface *surface, uint32_t key)
{
	tizen_keyrouter_unset_keygrab(tizen_keyrouter, surface, key);
	LOGD("request unset_keygrab (key:%d)!", key);
}

static void __do_keygrab(const char *keyname, uint32_t mode)
{
	xkb_keysym_t keysym = 0x0;
	int nkeycodes = 0;
	xkb_keycode_t *keycodes = NULL;
	int i;

	keysym = xkb_keysym_from_name(keyname, XKB_KEYSYM_NO_FLAGS);
	nkeycodes = __xkb_keycode_from_keysym(g_keymap, keysym, &keycodes);

	for (i = 0; i < nkeycodes; i++) {
		LOGD("%s's keycode is %d (nkeycode: %d)",
				keyname, keycodes[i], nkeycodes);
		__keygrab_request(keyrouter, NULL, keycodes[i], mode);
	}
	free(keycodes);
	keycodes = NULL;
}

static void __do_keyungrab(const char *keyname)
{
	xkb_keysym_t keysym = 0x0;
	int nkeycodes = 0;
	xkb_keycode_t *keycodes = NULL;
	int i;

	keysym = xkb_keysym_from_name(keyname, XKB_KEYSYM_NO_FLAGS);
	nkeycodes = __xkb_keycode_from_keysym(g_keymap, keysym, &keycodes);

	for (i = 0; i < nkeycodes; i++) {
		LOGD("%s's keycode is %d (nkeycode: %d)\n",
				keyname, keycodes[i], nkeycodes);
		__keyungrab_request(keyrouter, NULL, keycodes[i]);
	}
	free(keycodes);
	keycodes = NULL;
}

static int __xkb_init(void)
{
	if (!g_ctx) {
		g_ctx = xkb_context_new(0);
		if (!g_ctx) {
			LOGE("Failed to get xkb_context");
			return -1;
		}
	}

	return 0;
}

static void __xkb_fini(void)
{
	if (g_ctx) {
		xkb_context_unref(g_ctx);
		g_ctx = NULL;
	}
}

static void __input_device_info(void *data,
		struct tizen_input_device *tizen_input_device,
		const char *name, uint32_t class, uint32_t subclass,
		struct wl_array *axes)
{
	LOGD("device info - name: %s, class: %d, subclass: %d",
			name, class, subclass);
}

static void __input_device_event_device(void *data,
		struct tizen_input_device *tizen_input_device,
		unsigned int serial, const char *name, uint32_t time)
{
	LOGD("event device - name: %s, time: %d", name, time);
}

static void __input_device_axis(void *data,
		struct tizen_input_device *tizen_input_device,
		uint32_t axis_type, wl_fixed_t value)
{
	LOGD("axis - axis_type: %d, value: %lf",
			axis_type, wl_fixed_to_double(value));
}

static const struct tizen_input_device_listener input_device_listener = {
	__input_device_info,
	__input_device_event_device,
	__input_device_axis,
};

static void __cb_device_add(void *data,
		struct tizen_input_device_manager *tizen_input_device_manager,
		uint32_t serial, const char *name,
		struct tizen_input_device *device, struct wl_seat *seat)
{
	LOGD("%s device is added!", name);
	tizen_input_device_add_listener(device, &input_device_listener, NULL);
}

static void __cb_device_remove(void *data,
		struct tizen_input_device_manager *tizen_input_device_manager,
		uint32_t serial, const char *name,
		struct tizen_input_device *device, struct wl_seat *seat)
{
	LOGD("%s device is removed!", name);
	tizen_input_device_release(device);
}

static void __cb_error(void *data,
		struct tizen_input_device_manager *tizen_input_device_manager,
		uint32_t errorcode)
{
	LOGE("error: %d", errorcode);
}

static void __cb_block_expired(void *data,
		struct tizen_input_device_manager *tizen_input_device_manager)
{
	LOGD("block expired");
}

static struct tizen_input_device_manager_listener input_devmgr_listener = {
	__cb_device_add,
	__cb_device_remove,
	__cb_error,
	__cb_block_expired
};

static int __on_lock(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	amd_app_status_h app_status = arg3;
	int status;
	int caller_pid = arg2;
	amd_app_status_h caller_app_status;
	int caller_app_type;

	if (TIZEN_FEATURE_BLOCK_INPUT) {
		caller_app_status = amd_app_status_find_by_pid(caller_pid);
		if (!caller_app_status)
			return 0;

		caller_app_type = amd_app_status_get_app_type(
				caller_app_status);
		if (caller_app_type == AMD_AT_SERVICE_APP)
			return 0;

		status = amd_app_status_get_status(app_status);
		if (status != STATUS_VISIBLE && !arg1)
			__input_lock();
	}

	return 0;
}

static int __on_unlock(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	amd_app_status_h app_status = (amd_app_status_h)arg3;
	int status = arg1;
	int pid = amd_app_status_get_pid(app_status);

	if (TIZEN_FEATURE_BLOCK_INPUT) {
		if (latest_pid == pid && status == STATUS_VISIBLE)
			__input_unlock();
	}

	return 0;
}

static int __on_launch_complete(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	amd_appinfo_h ai = (amd_appinfo_h)arg3;
	const char *comptype;

	comptype = amd_appinfo_get_value(ai, AMD_AIT_COMPTYPE);
	if (comptype && !strcmp(comptype, APP_TYPE_UI))
		latest_pid = arg1;

	return 0;
}

static int __on_registry_handler(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	uint32_t id = (uint32_t)arg1;
	struct wl_registry *registry = (struct wl_registry *)arg3;

	if (!strcmp(msg, "wayland.listener.tizen_input_device_manager")) {
		if (!input_devmgr) {
			input_devmgr_id = id;
			input_devmgr = wl_registry_bind(registry, id,
				     &tizen_input_device_manager_interface,
				     2);
			LOGD("input_devmgr(%p)", input_devmgr);
		}
	} else if (!strcmp(msg, "wayland.listener.tizen_keyrouter")) {
		if (!keyrouter) {
			keyrouter_id = id;
			keyrouter = wl_registry_bind(registry, id,
					&tizen_keyrouter_interface, 1);
			LOGD("keyrouter(%p)", keyrouter);
		}
	} else if (!strcmp(msg, "wayland.listener.wl_seat")) {
		if (!seat) {
			seat_id = id;
			seat = wl_registry_bind(registry, id,
					&wl_seat_interface, 1);
			if (!seat)
				return -1;

			LOGD("seat(%p)", seat);
			keyboard = wl_seat_get_keyboard(seat);
			wl_keyboard_add_listener(keyboard, &keyboard_listener,
					NULL);
			LOGD("keyboard(%p)", keyboard);
		}
	}

	return 0;
}

static int __on_registry_remover(const char *msg, int arg1, int arg2, void *arg3,
		bundle *data)
{
	uint32_t id = (uint32_t)arg1;

	if (id == keyrouter_id && keyrouter) {
		tizen_keyrouter_destroy(keyrouter);
		keyrouter = NULL;
		keyrouter_id = 0;
		LOGW("tizen keyrouter is destroyed");
	}

	if (id == input_devmgr_id && input_devmgr) {
		tizen_input_device_manager_destroy(input_devmgr);
		input_devmgr = NULL;
		input_devmgr_id = 0;
		LOGW("tizen input device manager is destroyed");
	}

	if (id == seat_id && seat) {
		if (keyboard) {
			wl_keyboard_destroy(keyboard);
			keyboard = NULL;
		}

		wl_seat_destroy(seat);
		seat = NULL;
		seat_id = 0;
		LOGW("wl seat is destroyed");
	}

	return 0;
}

static int __input_init(void)
{
	if (!display) {
		display = amd_wayland_get_display();
		if (!display) {
			LOGD("Failed to connect to wayland compositor");
			return -1;
		}
	}

	if (__xkb_init() < 0)
		return -1;

	LOGD("Connected to wayland compositor!");

	if (input_devmgr == NULL) {
		LOGE("input_devmgr is null");
		return -1;
	}

	if (keyrouter == NULL) {
		LOGE("keyrouter is null");
		return -1;
	}

	if (seat == NULL) {
		LOGE("seat is null");
		return -1;
	}

	if (keyboard == NULL) {
		LOGE("keyboard is null");
		return -1;
	}

	if (tizen_input_device_manager_add_listener(input_devmgr,
		&input_devmgr_listener, NULL) < 0) {
		LOGE("Failed to add listener");
	}
	wl_display_flush(display);
	wl_display_roundtrip(display);

	if (g_keymap == NULL) {
		LOGE("g_keymap is null");
		return -1;
	}

	init_done = true;

	return 0;
}

EXPORT int AMD_MOD_INIT(void)
{
	LOGD("input init");

	_input_config_init();
	timeout_val = _input_config_get_timeout_interval();

	amd_noti_listen("wayland.listener.tizen_input_device_manager",
			__on_registry_handler);
	amd_noti_listen("wayland.listener.tizen_keyrouter",
			__on_registry_handler);
	amd_noti_listen("wayland.listener.wl_seat", __on_registry_handler);
	amd_noti_listen("wayland.listener_remove", __on_registry_remover);
	amd_noti_listen("app_status.update_status.start", __on_unlock);
	amd_noti_listen("launch.fail", __on_unlock);
	amd_noti_listen("launch.prepare.ui.end", __on_lock);
	amd_noti_listen("launch.complete.start", __on_launch_complete);
	__xkb_init();

	return 0;
}

EXPORT void AMD_MOD_FINI(void)
{
	__xkb_fini();
	if (sid > 0) {
		g_source_remove(sid);
		sid = 0;
	}
	_input_config_fini();
}

static int __input_lock(void)
{
	if (locked)
		__input_unlock();

	if (!init_done && __input_init() < 0)
		return -1;

	LOGD("call tizen_input_device_manager_block_events");
	tizen_input_device_manager_block_events(input_devmgr, 0,
		TIZEN_INPUT_DEVICE_MANAGER_CLAS_TOUCHSCREEN |
		TIZEN_INPUT_DEVICE_MANAGER_CLAS_MOUSE, timeout_val);
	timer = g_timeout_add(timeout_val, __timeout_handler, NULL);
	__do_keygrab("XF86Back", TIZEN_KEYROUTER_MODE_EXCLUSIVE);
	wl_display_roundtrip(display);

	locked = true;

	return 0;
}

static int __input_unlock(void)
{
	if (!locked)
		return 0;

	if (!init_done && __input_init() < 0)
		return -1;

	LOGD("call tizen_input_device_manager_unblock_events");
	tizen_input_device_manager_unblock_events(input_devmgr, 0);
	__do_keyungrab("XF86Back");
	wl_display_roundtrip(display);

	locked = false;
	if (timer > 0) {
		g_source_remove(timer);
		timer = 0;
	}

	return 0;
}
