/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd All Rights Reserved
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

#ifndef __AMD_INPUT_PRIVATE_H__
#define __AMD_INPUT_PRIVATE_H__

#include <dlog.h>

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "AMD_INPUT"

#ifndef _E
#define _E LOGE
#endif

#ifndef _W
#define _W LOGW
#endif

#ifndef _I
#define _I LOGI
#endif

#ifndef _D
#define _D LOGD
#endif

#ifdef EXPORT
#undef EXPORT
#endif

#define EXPORT __attribute__ ((visibility("default")))

#endif /* __AMD_INPUT_PRIVATE_H__ */
