/*
 * Copyright (c) 2017 Samsung Electronics Co., Ltd. All rights reserved.
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

#ifndef __APPCORE_UI_PLUGIN_H__
#define __APPCORE_UI_PLUGIN_H__

#include "appcore_ui_base.h"

void appcore_ui_plugin_init(appcore_ui_base_ops *ops, int argc, char **argv,
		unsigned int *hint);
void appcore_ui_plugin_fini(void);

#endif /* __APPCORE_UI_PLUGIN_H__ */
