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

#pragma once

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <app/bundle.h>
#include "aul_cmd.h"

#define AUL_SOCK_MAXBUFF 131071
#define ELOCALLAUNCH_ID 128
#define EILLEGALACCESS 127
#define ETERMINATING 126
#define ENOLAUNCHPAD 125
#define EREJECTED 123

#define AUL_PKT_HEADER_SIZE (sizeof(int) + sizeof(int) + sizeof(int))

typedef struct _app_pkt_t {
	int cmd;
	int len;
	int opt;
	unsigned char data[1];
} app_pkt_t;

typedef enum {
	AUL_SOCK_NONE = 0x0, /* default */
	AUL_SOCK_NOREPLY = 0x1, /* return immediately after packet sent without reply */
	AUL_SOCK_ASYNC = 0x2, /* leave fd in open and return fd of client socket */
	AUL_SOCK_QUEUE = 0x4, /* add request to pending list in case of receiver is busy */
	AUL_SOCK_BUNDLE = 0x8, /* has bundle */
} aul_sock_opt_e;

/*
 * This API is only for Appfw internally.
 */
int aul_sock_create_server(int pid, uid_t uid);

/*
 * This API is only for Appfw internally.
 */
int aul_sock_send_raw(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen, int opt);

/*
 * This API is only for Appfw internally.
 */
int aul_sock_send_bundle(int pid, uid_t uid, int cmd, bundle *kb, int opt);

/*
 * This API is only for Appfw internally.
 */
int aul_sock_send_raw_with_fd(int fd, int cmd, unsigned char *kb_data, int datalen, int opt);

/*
 * This API is only for Appfw internally.
 */
int aul_sock_send_bundle_with_fd(int fd, int cmd, bundle *kb, int opt);

/*
 * This API is only for Appfw internally.
 */
app_pkt_t *aul_sock_recv_pkt(int fd, int *clifd, struct ucred *cr);

/*
 * This API is only for Appfw internally.
 */
int aul_sock_create_launchpad_client(const char *pad_type, uid_t uid);

/*
 * This API is only for Appfw internally.
 */
int aul_sock_recv_reply_sock_fd(int fd, int (*ret_fd)[2], int num_of_ret_fd);

/*
 * This API is only for Appfw internally.
 */
int aul_sock_recv_reply_pkt(int fd, app_pkt_t **pkt);

/*
 * This API is only for Appfw internally.
 */
int aul_sock_set_sock_option(int fd, int cli);

/*
 * This API is only for Appfw internally.
 */
struct timeval aul_sock_get_rcv_timeval(void);

/*
 * This API in only for Appfw internally.
 */
int aul_sock_recv_pkt_with_cb(int fd,
		void (*callback)(app_pkt_t *pkt, void *data),
		void *user_data);

/*
 * This API in only for Appfw internally.
 */
int aul_sock_recv_result_with_fd(int fd);

/*
 * This API in only for Appfw internally.
 */
int aul_sock_destroy_server(int fd);

/**
 * This API is only for Appfw internally.
 */
int aul_sock_send_result(int fd, int res);
