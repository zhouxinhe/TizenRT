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

#ifndef __AMD_WATCHDOG_LOGGER_H__
#define __AMD_WATCHDOG_LOGGER_H__

int _watchdog_logger_init(void);

void _watchdog_logger_fini(void);

int _watchdog_logger_print(const char *tag, const char *format, ...);

#endif /* __AMD_WATCHDOG_LOGGER_H__ */
