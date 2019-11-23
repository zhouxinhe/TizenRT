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

#ifndef __AUL_RSC_MGR_INTERNAL_H__
#define __AUL_RSC_MGR_INTERNAL_H__

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "AUL_RESOURCE_MANAGER"

#define RSC_GROUP_TYPE_IMAGE "image"
#define RSC_GROUP_TYPE_LAYOUT "layout"
#define RSC_GROUP_TYPE_SOUND "sound"
#define RSC_GROUP_TYPE_BIN "bin"

#define RSC_NODE_ATTR_SCREEN_DPI "screen-dpi"
#define RSC_NODE_ATTR_SCREEN_DPI_RANGE "screen-dpi-range"
#define RSC_NODE_ATTR_SCREEN_WIDTH_RANGE "screen-width-range"
#define RSC_NODE_ATTR_SCREEN_LARGE "screen-large"
#define RSC_NODE_ATTR_SCREEN_BPP "screen-bpp"
#define RSC_NODE_ATTR_PLATFORM_VER "platform-version"
#define RSC_NODE_ATTR_LANGUAGE "language"

typedef struct {
	char *folder;
	bundle *attr;
} resource_node_t;

typedef struct {
	char *folder;
	char *type;
	GList *node_list;
} resource_group_t;

typedef struct {
	char *package;
	GList *group_list;
} resource_data_t;

int _resource_open(const char *path, resource_data_t **data);
int _resource_close(resource_data_t *data);

#endif
