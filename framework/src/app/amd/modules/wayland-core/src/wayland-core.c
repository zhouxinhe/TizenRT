/*
 * Copyright (c) 2017 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <glib.h>
#include <gio/gio.h>
#include <wayland-client.h>
#include <wayland-tbm-client.h>
#include <tizen-extension-client-protocol.h>
#include <amd.h>

#include "wayland-core-private.h"

#define PATH_RUN_WAYLAND "/run/wayland-0"
#define PATH_RUN_WMREADY "/run/.wm_ready"
#define PATH_RUN "/run"

static bool wl_ready;
static bool wm_ready;
static bool wl_initialized;
static struct wl_display *display;
static struct wl_registry *registry;
static amd_inotify_watch_info_h __wh;
static GIOChannel *__io;
static guint __sid;

static void __wl_listener_cb(void *data, struct wl_registry *reg,
		unsigned int id, const char *interface, unsigned int version)
{
	char buf[512];

	if (!interface)
		return;

	LOGW("interface(%s), id(%u), version(%u)", interface, id, version);
	snprintf(buf, sizeof(buf), "wayland.listener.%s", interface);
	amd_noti_send(buf, (int)id, (int)version, reg, NULL);
}

static void __wl_listener_remove_cb(void *data, struct wl_registry *reg,
		unsigned int id)
{
	LOGW("id(%u)", id);
	amd_noti_send("wayland.listener_remove", (int)id, 0, reg, NULL);
}

static const struct wl_registry_listener registry_listener = {
	__wl_listener_cb,
	__wl_listener_remove_cb
};

static gboolean __wl_display_cb(GIOChannel *io, GIOCondition cond,
		gpointer data)
{
	int r;
	GPollFD poll_fd;

	if (cond & (G_IO_ERR | G_IO_HUP)) {
		LOGE("Recevied error - cond(%d)", cond);
		__sid = 0;
		return G_SOURCE_REMOVE;
	}

	if (cond & (G_IO_IN | G_IO_PRI)) {
		poll_fd.fd = wl_display_get_fd(display);
		if (poll_fd.fd < 0) {
			LOGE("invalid display");
			__sid = 0;
			return G_SOURCE_REMOVE;
		}

		poll_fd.events = G_IO_IN | G_IO_PRI;
		if (g_poll(&poll_fd, 1, 0) != 1) {
			LOGW("events have been processed already");
			return G_SOURCE_CONTINUE;
		}

		r = wl_display_dispatch(display);
		if (r < 0 && ((errno != EAGAIN) && (errno != EINVAL))) {
			LOGE("result(%d), errno(%d)", r, errno);
			__sid = 0;
			return G_SOURCE_REMOVE;
		}
	}

	return G_SOURCE_CONTINUE;
}

static gboolean __init_wl(gpointer data)
{
	GIOCondition cond = G_IO_IN | G_IO_PRI | G_IO_ERR | G_IO_HUP;
	int r;
	int fd;

	display = wl_display_connect(NULL);
	if (display == NULL) {
		LOGE("Failed to connect wayland display");
		return G_SOURCE_CONTINUE;
	}

	registry = wl_display_get_registry(display);
	if (registry == NULL) {
		LOGE("Failed to get wayland registry");
		wl_display_disconnect(display);
		display = NULL;
		return G_SOURCE_CONTINUE;
	}

	wl_registry_add_listener(registry, &registry_listener, NULL);
	wl_display_flush(display);
	r = wl_display_roundtrip(display);
	if (r < 0)
		LOGW("wl_display_roundtrip() is failed. %d", r);

	amd_wayland_set_display(display);

	fd = wl_display_get_fd(display);
	if (fd < 0) {
		LOGE("Failed to get fd from wl_display");
		return G_SOURCE_REMOVE;
	}

	__io = g_io_channel_unix_new(fd);
	if (__io == NULL) {
		LOGE("Failed to create gio channel");
		return G_SOURCE_REMOVE;
	}

	__sid = g_io_add_watch(__io, cond, __wl_display_cb, NULL);
	if (__sid == 0)
		LOGE("Failed to add watch");

	return G_SOURCE_REMOVE;
}

static bool __wayland_monitor_cb(const char *event_name, void *data)
{
	if (event_name == NULL)
		return true;

	if (strcmp(event_name, "wayland-0") == 0) {
		LOGD("%s is created", event_name);
		wl_ready = true;
	} else if (strcmp(event_name, ".wm_ready") == 0) {
		LOGD("%s is created", event_name);
		wm_ready = true;
	}

	if (wm_ready && wl_ready) {
		wl_initialized = true;
		g_idle_add(__init_wl, NULL);
		__wh = NULL;
		return false;
	}

	return true;
}

static gboolean __idle_cb(gpointer data)
{
	LOGD("wayland core init");

	if (access(PATH_RUN_WAYLAND, F_OK) == 0) {
		LOGD("%s exists", PATH_RUN_WAYLAND);
		wl_ready = true;
	}

	if (access(PATH_RUN_WMREADY, F_OK) == 0) {
		LOGD("%s exists", PATH_RUN_WMREADY);
		wm_ready = true;
	}

	if (wl_ready && wm_ready) {
		wl_initialized = true;
		g_idle_add(__init_wl, NULL);
		return G_SOURCE_REMOVE;
	}

	__wh = amd_inotify_add_watch(PATH_RUN, IN_CREATE,
			__wayland_monitor_cb, NULL);
	if (__wh == NULL) {
		LOGE("Failed to add inotify watch");
		return G_SOURCE_CONTINUE;
	}

	return G_SOURCE_REMOVE;
}

EXPORT int AMD_MOD_INIT(void)
{
	LOGD("wayland core init");

	g_idle_add(__idle_cb, NULL);

	return 0;
}

EXPORT void AMD_MOD_FINI(void)
{
	LOGD("wayland core finish");

	if (__sid)
		g_source_remove(__sid);

	if (__io)
		g_io_channel_unref(__io);

	if (__wh)
		amd_inotify_rm_watch(__wh);

	if (registry) {
		wl_registry_destroy(registry);
		registry = NULL;
	}

	if (display) {
		wl_display_disconnect(display);
		display = NULL;
		amd_wayland_set_display(display);
	}
}
