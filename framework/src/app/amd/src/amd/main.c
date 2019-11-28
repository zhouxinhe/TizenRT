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
#include <stdio.h>
#include <dlfcn.h>

#define PATH_LIB_AMD "/usr/share/amd/libamd.so"

int main(int argc, char *argv[])
{
	void *handle;
	int (*dl_main)(int, char **);

	handle = dlopen(PATH_LIB_AMD, RTLD_LAZY | RTLD_GLOBAL);
	if (!handle) {
		fprintf(stderr, "Failed to load - %s", dlerror());
		return -1;
	}

	dl_main = dlsym(handle, "main");
	if (!dl_main) {
		fprintf(stderr, "Failed to find main function");
		dlclose(handle);
		return -1;
	}

	return dl_main(argc, argv);
}
