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

#include <Elementary.h>
#include "app_extension.h"

static void __set_preinit_window_name(const char *win_name, void *win)
{
	const Evas *e;
	Ecore_Evas *ee;

	if (!win_name || !win)
		return;

	e = evas_object_evas_get((const Evas_Object *)win);
	if (e) {
		ee = ecore_evas_ecore_evas_get(e);
		if (ee)
			ecore_evas_name_class_set(ee, win_name, win_name);
	}
}

void *app_get_preinitialized_window(const char *win_name)
{
	void *win;

	win = elm_win_precreated_object_get();
	if (win == NULL)
		return NULL;

	__set_preinit_window_name(win_name, win);
	elm_win_precreated_object_set(NULL);

	return win;
}

void *app_get_preinitialized_background(void)
{
	void *background;

	background = elm_bg_precreated_object_get();
	if (background == NULL)
		return NULL;

	elm_bg_precreated_object_set(NULL);

	return background;
}

void *app_get_preinitialized_conformant(void)
{
	void *conformant;

	conformant = elm_conformant_precreated_object_get();
	if (conformant == NULL)
		return NULL;

	elm_conformant_precreated_object_set(NULL);

	return conformant;
}

