/* ****************************************************************
*
* Copyright 2017 Samsung Electronics All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
******************************************************************/

#include <tinyara/config.h>

#include <stdio.h>
#include <pthread.h>
#include "st_things_sample.h"

#ifndef CONFIG_ST_THINGS_SAMPLE_THREAD_STACKSIZE
#define CONFIG_ST_THINGS_SAMPLE_THREAD_STACKSIZE 4096
#endif

//extern int utils_stackmonitor(int argc, char **args);
extern int utils_heapinfo(int argc, char **args);

static void *st_things_sample(void *param)
{
	//utils_stackmonitor(0, NULL);

	//utils_heapinfo(0, NULL);

	printf("st_things_sample!!\n");

	ess_process();

	return 0;
}

#ifdef CONFIG_BUILD_KERNEL
int main(int argc, FAR char *argv[])
#else
int st_things_sample_main(int argc, char *argv[])
#endif
{
	pthread_attr_t attr;
	struct sched_param sparam;
	sparam.sched_priority = 100;

	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, CONFIG_ST_THINGS_SAMPLE_THREAD_STACKSIZE);
	pthread_attr_setschedparam(&attr, &sparam);

	int status;
	pthread_t thread;
	status = pthread_create(&thread, &attr, st_things_sample, NULL);
	if (status != 0) {
		printf("[%s] pthread_create failed, status=%d\n", __FUNCTION__, status);
		return 0;
	}

	pthread_setname_np(thread, "st_things_sample_main");
	pthread_join(thread, NULL);
	return 0;
}
