/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd All Rights Reserved
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

#ifndef __AUL_COMPLICATION_H__
#define __AUL_COMPLICATION_H__

#ifdef __cplusplus
extern "C" {
#endif

#define AUL_K_COMPLICATION_MODE		"__AUL_COMPLICATION_MODE__"

#define UPDATE_REQUEST		"__UPDATE_REQUEST__"
#define LAUNCH_REQUEST		"__LAUNCH_REQUEST__"

int aul_complication_update_request(const char *appid, const char *provider_appid, uid_t uid);
int aul_complication_launch_with_extra_data(const char *appid,
		const char *provider_appid, uid_t uid, const char *key, char *value);

#ifdef __cplusplus
}
#endif

#endif /* __AUL_COMPLICATION_H__ */
