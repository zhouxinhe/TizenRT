/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include <xdgmime.h>

#include "aul.h"
#include "aul_api.h"
#include "miregex.h"
#include "menu_db_util.h"
#include "aul_util.h"

static int __match_content_with_regex(const char *content, regex_t *regex_preg)
{
	if (regexec(regex_preg, content, 0, NULL, 0) == 0)
		return 1;
	else
		return 0;
}

API int aul_get_mime_from_content(const char *content, char *mimetype,
				     int len)
{
	char *founded = NULL;
	regex_tbl *miregex_tbl = NULL;

	if (content == NULL)
		return AUL_R_EINVAL;

	if ((miregex_tbl = miregex_get_regex_table()) == NULL) {
		_E("load miregex_table fail");
		return AUL_R_ERROR;
	}

	while (miregex_tbl) {
		if (__match_content_with_regex(content,
			&(miregex_tbl->regex_preg))) {
			founded = miregex_tbl->mimetype;
			SECURE_LOGD("content %s => mimetype %s", content, founded);
			break;
		}
		miregex_tbl = miregex_tbl->next;
	}

	if (founded != NULL)
		snprintf(mimetype, len, "%s", founded);
	else {
		/* TODO : should to try to extract from share mime info's data*/
		return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_get_mime_description(const char *mimetype, char *desc, int len)
{
	regex_tbl *miregex_tbl = NULL;
	char *founded = NULL;

	if (mimetype == NULL)
		return AUL_R_EINVAL;

	if ((miregex_tbl = miregex_get_regex_table()) == NULL) {
		_E("load miregex_table fail");
		return AUL_R_ERROR;
	}

	while (miregex_tbl) {
		if (strcmp(miregex_tbl->mimetype, mimetype) == 0) {
			founded = miregex_tbl->desc;
			_D("mimetype %s => desc %s", mimetype, founded);
			break;
		}
		miregex_tbl = miregex_tbl->next;
	}

	if (founded != NULL)
		snprintf(desc, len, "%s", founded);
	else {
		/* TODO : should to try to extract from share mime info's comment */
		return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_get_mime_extension(const char *mimetype, char *ext, int len)
{
	const char **extlist;
	int totlen = 0;
	const char *unaliased_mimetype;

	if (mimetype == NULL || ext == NULL || len <= 0)
		return AUL_R_EINVAL;

	unaliased_mimetype = xdg_mime_unalias_mime_type(mimetype);
	if (unaliased_mimetype == NULL)
		return AUL_R_ERROR;

	extlist = xdg_mime_get_file_names_from_mime_type(unaliased_mimetype);
	if (extlist == NULL)
		return AUL_R_ERROR;

	if (extlist[0] == NULL)
		return AUL_R_ERROR;

	ext[0] = 0;
	while (*extlist != NULL) {
		if (*(extlist + 1) == NULL) {
			snprintf(&ext[totlen], len - totlen, "%s", *extlist);
			break;
		} else {
			snprintf(&ext[totlen], len - totlen, "%s,", *extlist);
			if (strlen(*extlist) > len - totlen - 1)
				break;
			totlen += strlen(*extlist) + 1;
			extlist++;
		}
	}

	return AUL_R_OK;
}

API int aul_get_mime_icon(const char *mimetype, char *iconname, int len)
{
	const char *icon;
	const char *unaliased_mimetype;

	if (mimetype == NULL || iconname == NULL || len <= 0)
		return AUL_R_EINVAL;

	unaliased_mimetype = xdg_mime_unalias_mime_type(mimetype);
	if (unaliased_mimetype == NULL)
		return AUL_R_ERROR;

	icon = xdg_mime_get_icon(unaliased_mimetype);
	if (icon == NULL)
		icon = xdg_mime_get_generic_icon(unaliased_mimetype);

	if (icon != NULL) {
		snprintf(iconname, len, "%s", icon);
		return AUL_R_OK;
	} else
		return AUL_R_ERROR;
}

API int aul_get_mime_from_file(const char *filename, char *mimetype, int len)
{
	const char *mime;
	if (filename == NULL)
		return AUL_R_EINVAL;

	if (access(filename, F_OK) != 0)
		return AUL_R_EINVAL;

	mime = xdg_mime_get_mime_type_for_file(filename, 0);
	if (strcmp(mime, "application/octet-stream") == 0)
		mime = xdg_mime_get_mime_type_from_file_name(filename);

	snprintf(mimetype, len, "%s", mime);
	return AUL_R_OK;
}

API int aul_set_defapp_with_mime(const char *mimetype, const char *defapp)
{
	/* removed */
	return 0;
}

API int aul_get_defapp_from_mime(const char *mimetype, char *defapp, int len)
{
	/* removed */
	return 0;
}

API int aul_open_content(const char *content)
{
	/* removed */
	return 0;
}

API int aul_open_file_with_mimetype(const char *filename,
				       const char *mimetype)
{
	/* removed */
	return 0;
}

API int aul_open_file(const char *filename)
{
	/* removed */
	return 0;
}

