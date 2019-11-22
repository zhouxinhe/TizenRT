/*
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <aul_rsc_mgr.h>
#include "app_resource_manager.h"

int app_resource_manager_init()
{
	return aul_resource_manager_init();
}

int app_resource_manager_get(app_resource_e type, const char *id, char **path)
{
	return aul_resource_manager_get((aul_resource_e)type, id, path);
}

int app_resource_manager_release()
{
	return aul_resource_manager_release();
}

