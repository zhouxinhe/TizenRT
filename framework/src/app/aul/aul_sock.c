/*
 * Copyright (c) 2000 - 2018 Samsung Electronics Co., Ltd. All rights reserved.
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
// #include <sys/xattr.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
// #include <tzplatform_config.h>
#include <glib.h>
#include <vconf.h>

#include "aul_api.h"
#include "aul_sock.h"
#include "aul_util.h"

#define MAX_NR_OF_DESCRIPTORS 2
#define MAX_PAYLOAD_SIZE	(1024 * 1024 * 1)
#define PATH_AMD_SOCK "/run/aul/daemons/.amd-sock"

#define REGULAR_UID_MIN 5000

typedef struct app_pkt_header_s {
	int cmd;
	int len;
	int opt;
} app_pkt_header_t;

static int socket_timeout_initialized;

static struct timeval tv = { 5, 200 * 1000 }; /* 5.2 */

static int __connect_client_sock(int sockfd, const struct sockaddr *saptr,
		socklen_t salen, int nsec);

static int __recv_raw(int fd, unsigned char *data, size_t data_size)
{
	ssize_t recv_size = 0;
	ssize_t r;
	size_t size = data_size;
	bool is_blocking;

	if (fcntl(fd, F_GETFL, 0) & O_NONBLOCK)
		is_blocking = false;
	else
		is_blocking = true;

	while (size > 0) {
		r = recv(fd, data, size, 0);
		if (r == 0) {
			_W("Socket was disconnected. fd(%d)", fd);
			return -ECOMM;
		} else if (r < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				if (is_blocking && errno == EAGAIN) {
					_E("recv timeout. fd(%d)", fd);
					return -EAGAIN;
				}

				continue;
			}

			_E("recv error. fd(%d), errno(%d)",
					fd, errno);
			return -ECOMM;
		}

		size -= r;
		data += r;
		recv_size += r;
	}

	if (recv_size != data_size) {
		_E("Failed to receive messages. fd(%d)", fd);
		return -ECOMM;
	}

	return 0;
}

static int __recv_pkt(int fd, app_pkt_t **out_pkt)
{
	app_pkt_header_t header = { 0, };
	app_pkt_t *pkt;
	int r;

	*out_pkt = NULL;
	r = __recv_raw(fd, (unsigned char *)&header, sizeof(header));
	if (r < 0) {
		_E("Failed to receive packet header");
		return r;
	}

	if (header.len < 0 || header.len > MAX_PAYLOAD_SIZE) {
		_E("Invalid protocol. length(%d)", header.len);
		return -ECOMM;
	}

	pkt = calloc(1, sizeof(app_pkt_t) + header.len);
	if (!pkt) {
		_E("Out of memory");
		return -ECOMM;
	}
	pkt->cmd = header.cmd;
	pkt->len = header.len;
	pkt->opt = header.opt;

	r = __recv_raw(fd, (unsigned char *)pkt->data, pkt->len);
	if (r < 0) {
		free(pkt);
		return r;
	}

	*out_pkt = pkt;

	return 0;
}

static void __set_timeval(double sec)
{
	char buf[12];
	gchar *ptr = NULL;

	snprintf(buf, sizeof(buf), "%.3f", sec);
	tv.tv_sec = g_ascii_strtoull(buf, &ptr, 10);
	tv.tv_usec = g_ascii_strtoull(ptr + 1, &ptr, 10) * 1000;
	_D("tv_sec: %ld, tv_usec: %ld", (long)tv.tv_sec, (long)tv.tv_usec);
}

static void __socket_timeout_vconf_cb(keynode_t *key, void *data)
{
	const char *name;
	double sec;

	name = vconf_keynode_get_name(key);
	if (name && strcmp(name, VCONFKEY_AUL_SOCKET_TIMEOUT) == 0) {
		sec = vconf_keynode_get_dbl(key);
		__set_timeval(sec);
	}
}

static void __init_socket_timeout(void)
{
	int r;
	double sec = 5.2f;

	r = access("/run/aul/.socket_timeout", F_OK);
	if (r < 0) {
		socket_timeout_initialized = 1;
		return;
	}

	r = vconf_get_dbl(VCONFKEY_AUL_SOCKET_TIMEOUT, &sec);
	if (r < 0)
		_D("Failed to get vconf: %s", VCONFKEY_AUL_SOCKET_TIMEOUT);

	r = vconf_notify_key_changed(VCONFKEY_AUL_SOCKET_TIMEOUT,
			__socket_timeout_vconf_cb, NULL);
	if (r < 0) {
		_E("Failed to register callback for %s",
				VCONFKEY_AUL_SOCKET_TIMEOUT);
		return;
	}

	__set_timeval(sec);
	socket_timeout_initialized = 1;
}

API struct timeval aul_sock_get_rcv_timeval(void)
{
	return tv;
}

API int aul_sock_set_sock_option(int fd, int cli)
{
	int size;
	int r;

	size = AUL_SOCK_MAXBUFF;
	r = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	if (r < 0)
		return r;

	r = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	if (r < 0)
		return r;

	if (cli) {
		if (TIZEN_FEATURE_SOCKET_TIMEOUT && !socket_timeout_initialized)
			__init_socket_timeout();
		r = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		if (r < 0)
			return r;
	}

	return 0;
}

static int __create_socket_dir(int pid, uid_t uid)
{
	char path[PATH_MAX];

	if (uid < REGULAR_UID_MIN)
		snprintf(path, sizeof(path), "/run/aul/daemons/%d", uid);
	else
		snprintf(path, sizeof(path), "/run/aul/apps/%d/%d", uid, pid);

	if (mkdir(path, 0700) != 0) {
		if (errno == EEXIST) {
			if (access(path, R_OK) != 0) {
				_E("Failed to acess %s directory", path);
				return -1;
			}
		} else {
			_E("Failed to create %s directory", path);
			return -1;
		}
	}

	return 0;
}

static void __create_socket_path(char *path_buf, int size, int pid, uid_t uid)
{
	if (uid < REGULAR_UID_MIN) {
		snprintf(path_buf, size,
			"/run/aul/daemons/%d/.app-sock-%d", uid, pid);
	} else {
		snprintf(path_buf, size,
			"/run/aul/apps/%d/%d/.app-sock", uid, pid);
	}
}

static void __create_socket_link(const char *socket_path, int pid, uid_t uid)
{
	char path[PATH_MAX];

	if (__create_socket_dir(pid, uid) < 0)
		return;

	__create_socket_path(path, sizeof(path), pid, uid);
	if (link(socket_path, path) < 0) {
		if (errno == EEXIST)
			_D("path(%s) - already exists", path);
		else
			_E("path(%s) - unknown create error", path);
	}
}

API int aul_sock_create_server(int pid, uid_t uid)
{
	struct sockaddr_un saddr;
	int fd;
	int env_pid = -1;
	char *env_str;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	/*  support above version 2.6.27*/
	if (fd < 0) {
		if (errno == EINVAL) {
			fd = socket(AF_UNIX, SOCK_STREAM, 0);
			if (fd < 0) {
				_E("second chance - socket create error");
				return -1;
			}
		} else {
			_E("socket error");
			return -1;
		}
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sun_family = AF_UNIX;

	if (__create_socket_dir(pid, uid) < 0) {
		close(fd);
		return -1;
	}

	__create_socket_path(saddr.sun_path, sizeof(saddr.sun_path), pid, uid);
	unlink(saddr.sun_path);

	/* labeling to socket for SMACK */
	if (getuid() == 0) {	/* this is meaningful if current user is ROOT */
		if (fsetxattr(fd, "security.SMACK64IPOUT", "@", 1, 0) < 0) {
			/* in case of unsupported filesystem on 'socket' */
			/* or permission error by using 'emulator', bypass*/
			if ((errno != EOPNOTSUPP) && (errno != EPERM)) {
				_E("labeling to socket(IPOUT) error");
				close(fd);
				return -1;
			}
		}
		if (fsetxattr(fd, "security.SMACK64IPIN", "*", 1, 0) < 0) {
			/* in case of unsupported filesystem on 'socket' */
			/* or permission error by using 'emulator', bypass*/
			if ((errno != EOPNOTSUPP) && (errno != EPERM)) {
				_E("labeling to socket(IPIN) error");
				close(fd);
				return -1;
			}
		}
	}

	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		_E("bind error");
		close(fd);
		return -1;
	}

	aul_sock_set_sock_option(fd, 0);

	if (listen(fd, 128) == -1) {
		_E("listen error");
		close(fd);
		return -1;
	}

	/* Create socket link */
	if (pid > 0) {
		env_str = getenv("AUL_PID");
		if (env_str && isdigit(env_str[0]))
			env_pid = atoi(env_str);

		if (env_pid > 1 && pid != env_pid)
			__create_socket_link(saddr.sun_path, env_pid, uid);
	}

	return fd;
}

static int __create_client_sock(int pid, uid_t uid)
{
	int fd = -1;
	struct sockaddr_un saddr = { 0, };
	int retry = 2;
	int ret = -1;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	/*  support above version 2.6.27*/
	if (fd < 0) {
		if (errno == EINVAL) {
			fd = socket(AF_UNIX, SOCK_STREAM, 0);
			if (fd < 0) {
				_E("second chance - socket create error");
				return -1;
			}
		} else {
			_E("socket error");
			return -1;
		}
	}

	saddr.sun_family = AF_UNIX;
	if (pid == AUL_UTIL_PID) {
		snprintf(saddr.sun_path, sizeof(saddr.sun_path),
				"%s", PATH_AMD_SOCK);
	} else {
		__create_socket_path(saddr.sun_path, sizeof(saddr.sun_path), pid, uid);
	}

retry_con:
	ret = __connect_client_sock(fd, (struct sockaddr *)&saddr, sizeof(saddr),
			100 * 1000);
	if (ret < -1) {
		_E("maybe peer not launched or peer(%d:%u) dead. fd(%d)",
				pid, uid, fd);
		if (retry > 0) {
			usleep(100 * 1000);
			retry--;
			goto retry_con;
		}
	}

	if (ret < 0) {
		_E("Failed to connect the socket. fd(%d), errno(%d)",
				fd, errno);
		close(fd);
		return -1;
	}

	aul_sock_set_sock_option(fd, 1);

	return fd;
}

static int __connect_client_sock(int fd, const struct sockaddr *saptr, socklen_t salen,
		   int nsec)
{
	int flags;
	int ret;
	int error = 0;
	socklen_t len;
	fd_set readfds;
	fd_set writefds;
	struct timeval timeout;

	flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	ret = connect(fd, (struct sockaddr *)saptr, salen);
	if (ret < 0) {
		if (errno != EAGAIN && errno != EINPROGRESS) {
			(void)fcntl(fd, F_SETFL, flags);
			return -2;
		}
	}

	/* Do whatever we want while the connect is taking place. */
	if (ret == 0)
		goto done;	/* connect completed immediately */

	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	writefds = readfds;
	timeout.tv_sec = 0;
	timeout.tv_usec = nsec;

	ret = select(fd + 1, &readfds, &writefds, NULL, nsec ? &timeout : NULL);
	if (ret == 0) {
		errno = ETIMEDOUT;
		return -1;
	}

	if (FD_ISSET(fd, &readfds) || FD_ISSET(fd, &writefds)) {
		len = sizeof(error);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
			return -1;	/* Solaris pending error */
	}

	return -1;	/* select error: sockfd not set*/

done:
	ret = fcntl(fd, F_SETFL, flags);
	if (ret < 0)
		return ret;

	return 0;
}

static int __send_raw_async_with_fd(int fd, int cmd, unsigned char *kb_data, int datalen, int opt)
{
	int len;
	int sent = 0;
	app_pkt_t *pkt = NULL;

	pkt = (app_pkt_t *)calloc(1, sizeof(app_pkt_t) + datalen);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return -ENOMEM;
	}

	pkt->cmd = cmd;
	pkt->len = datalen;
	pkt->opt = opt;

	if (kb_data)
		memcpy(pkt->data, kb_data, pkt->len);

	while (sent != AUL_PKT_HEADER_SIZE + pkt->len) {
		len = send(fd, (char *)pkt + sent,
				AUL_PKT_HEADER_SIZE + pkt->len - sent,
				MSG_NOSIGNAL);
		if (len <= 0) {
			_E("send error fd:%d (errno %d)", fd, errno);
			free(pkt);
			return -ECOMM;
		}
		sent += len;
	}

	free(pkt);

	return 0;
}

API int aul_sock_send_raw_with_fd(int fd, int cmd, unsigned char *kb_data, int datalen, int opt)
{
	int len;
	int res;

	_D("fd(%d): cmd(%d)", fd, cmd);

	res = __send_raw_async_with_fd(fd, cmd, kb_data, datalen, opt);
	if (res < 0 || opt & AUL_SOCK_NOREPLY) {
		if (!(opt & AUL_SOCK_ASYNC))
			close(fd);
		return res;
	}

	if (opt & AUL_SOCK_ASYNC)
		return fd;

	len = __recv_raw(fd, (unsigned char *)&res, sizeof(int));
	if (len < 0)
		res = len;

	close(fd);

	return res;
}

API int aul_sock_send_bundle_with_fd(int fd, int cmd, bundle *kb, int opt)
{
	bundle_raw *kb_data = NULL;
	int datalen;
	int res;

	if (!kb)
		return -EINVAL;

	res = bundle_encode(kb, &kb_data, &datalen);
	if (res != BUNDLE_ERROR_NONE)
		return -EINVAL;

	res = aul_sock_send_raw_with_fd(fd, cmd, kb_data, datalen, opt | AUL_SOCK_BUNDLE);

	if (kb_data)
		free(kb_data);

	return res;
}

/*
 * @brief	Send data (in raw) to the process with 'pid' via socket
 */
API int aul_sock_send_raw(int pid, uid_t uid, int cmd,
		unsigned char *kb_data, int datalen, int opt)
{
	int fd;
	int r;

	_D("pid(%d): cmd(%d)", pid, cmd);

	fd = __create_client_sock(pid, uid);
	if (fd < 0)
		return -ECOMM;

	r = aul_sock_send_raw_with_fd(fd, cmd, kb_data, datalen, opt);
	if (r < 0) {
		if (opt & AUL_SOCK_ASYNC)
			close(fd);
	}

	return r;
}

API int aul_sock_send_bundle(int pid, uid_t uid, int cmd, bundle *kb, int opt)
{
	bundle_raw *kb_data = NULL;
	int datalen;
	int res;

	if (!kb)
		return -EINVAL;

	res = bundle_encode(kb, &kb_data, &datalen);
	if (res != BUNDLE_ERROR_NONE)
		return -EINVAL;

	res = aul_sock_send_raw(pid, uid, cmd, kb_data, datalen, opt | AUL_SOCK_BUNDLE);

	if (kb_data)
		free(kb_data);

	return res;
}

API app_pkt_t *aul_sock_recv_pkt(int fd, int *clifd, struct ucred *cr)
{
	struct sockaddr_un aul_addr = { 0, };
	int sun_size = sizeof(struct sockaddr_un);
	int cl = sizeof(struct ucred);
	app_pkt_t *pkt = NULL;
	int client_fd;
	int ret;

	client_fd = accept(fd, (struct sockaddr *)&aul_addr,
			(socklen_t *)&sun_size);
	if (client_fd == -1) {
		if (errno != EINTR)
			_E("accept error");
		return NULL;
	}

	ret = getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED,
			cr, (socklen_t *)&cl);
	if (ret < 0) {
		_E("peer information error");
		close(client_fd);
		return NULL;
	}

	aul_sock_set_sock_option(client_fd, 1);

	ret = __recv_pkt(client_fd, &pkt);
	if (ret < 0) {
		close(client_fd);
		return NULL;
	}

	*clifd = client_fd;

	return pkt;
}

API int aul_sock_recv_reply_pkt(int fd, app_pkt_t **ret_pkt)
{
	int ret;

	ret = __recv_pkt(fd, ret_pkt);
	close(fd);

	return ret;
}

static int __get_descriptors(struct cmsghdr *cmsg, struct msghdr *msg, int *fds, int maxdesc)
{
	int retnr = 0;
	int nrdesc;
	int payload;
	int *recvdesc;
	int i;

	if (cmsg == NULL || msg == NULL)
		return 0;
	if (cmsg->cmsg_type != SCM_RIGHTS)
		return 0;

	if (msg->msg_controllen > 0) {
		payload = cmsg->cmsg_len - sizeof(*cmsg);
		recvdesc = (int *)CMSG_DATA(cmsg);

		nrdesc = payload / sizeof(int);
		retnr = nrdesc < maxdesc ? nrdesc : maxdesc;
		for (i = 0; i < nrdesc; ++i) {
			if (maxdesc-- > 0)
				*fds++ = *recvdesc++;
			else
				close(*recvdesc++);
		}
	}

	return retnr;
}

static int __recv_message(int sock, struct iovec *vec, int vec_max_size, int *vec_size,
		int *fds, int *nr_fds)
{
	char buff[CMSG_SPACE(sizeof(int) * MAX_NR_OF_DESCRIPTORS) + CMSG_SPACE(50)] = {0};
	struct msghdr msg = {0};
	struct cmsghdr *cmsg = NULL;
	int ret;

	if (vec == NULL || vec_max_size < 1 || vec_size == NULL)
		return -EINVAL;

	msg.msg_iov = vec;
	msg.msg_iovlen = vec_max_size;
	msg.msg_control = buff;
	msg.msg_controllen = sizeof(buff);

	ret = recvmsg(sock, &msg, 0);
	if (ret < 0)
		return -errno;
	*vec_size = msg.msg_iovlen;

	/* get the ANCILLARY data */
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL) {
		if (nr_fds != NULL)
			*nr_fds = 0;
	} else {
		int iter = 0;
		int fdnum = 0;

		for (; cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg), iter++) {
			switch (cmsg->cmsg_type) {
			case SCM_RIGHTS:
				if (fds != NULL)
					fdnum = __get_descriptors(cmsg, &msg, fds, MAX_NR_OF_DESCRIPTORS);
				if (nr_fds != NULL)
					*nr_fds = fdnum;
				break;
			}
		}
	}

	return 0;
}

int aul_sock_recv_reply_sock_fd(int fd, int (*ret_fd)[2], int fd_size)
{
	int fds[2] = {0,};
	char recv_buff[1024];
	struct iovec vec[3];
	int ret = 0;
	int vec_len = 0;
	int fds_len = 0;

	vec[0].iov_base = recv_buff;
	vec[0].iov_len = sizeof(recv_buff);
	ret = __recv_message(fd, vec, 1, &vec_len, fds, &fds_len);
	if (ret < 0) {
		_E("Error[%d]. while receiving message", -ret);
		if (fds_len > 0)
			close(fds[0]);

		ret = -ECOMM;
	} else if ((fds_len == fd_size) && (fds_len == 2)) {
		(*ret_fd)[0] = fds[0];
		(*ret_fd)[1] = fds[1];
	} else if ((fds_len == fd_size) && (fds_len == 1)) {
		(*ret_fd)[0] = fds[0];
	} else {
		_E("wrong number of FD recevied. Expected:%d Actual:%d", fd_size, fds_len);
		ret = -ECOMM;
	}

	close(fd);
	return ret;
}

int aul_sock_create_launchpad_client(const char *pad_type, uid_t uid)
{
	int fd = -1;
	struct sockaddr_un saddr = { 0, };
	int retry = 1;
	int ret = -1;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	/*  support above version 2.6.27*/
	if (fd < 0) {
		if (errno == EINVAL) {
			fd = socket(AF_UNIX, SOCK_STREAM, 0);
			if (fd < 0) {
				_E("second chance - socket create error");
				return -1;
			}
		} else {
			_E("socket error");
			return -1;
		}
	}

	saddr.sun_family = AF_UNIX;
	snprintf(saddr.sun_path, sizeof(saddr.sun_path),
				"/run/aul/daemons/%d/%s", uid, pad_type);
retry_con:
	ret = __connect_client_sock(fd, (struct sockaddr *)&saddr,
				sizeof(saddr), 100 * 1000);
	if (ret < -1) {
		_E("maybe peer not launched or peer dead");
		if (retry > 0) {
			usleep(100 * 1000);
			retry--;
			goto retry_con;
		}
	}
	if (ret < 0) {
		close(fd);
		return -1;
	}

	aul_sock_set_sock_option(fd, 1);

	return fd;
}

int aul_sock_recv_pkt_with_cb(int fd,
		void (*callback)(app_pkt_t *pkt, void *data),
		void *user_data)
{
	app_pkt_t **pkt;
	int count = 0;
	size_t size;
	int ret;
	int i;

	if (fd < 0 || fd > sysconf(_SC_OPEN_MAX)) {
		_E("Invalid parameter");
		return -1;
	}

	if (callback == NULL) {
		_E("Invalid parameter");
		close(fd);
		return -1;
	}

	ret = __recv_raw(fd, (unsigned char *)&count, sizeof(int));
	if (ret < 0) {
		_E("recv error - %d", ret);
		close(fd);
		return ret;
	} else if (count <= 0 || count > MAX_RUNNING_INSTANCE) {
		_E("error - count: %d", count);
		close(fd);
		return -ECOMM;
	}

	size = sizeof(app_pkt_t *) * count;
	_D("count: %d, size: %d", count, size);
	pkt = (app_pkt_t **)calloc(1, size);
	if (pkt == NULL) {
		_E("out of memory");
		close(fd);
		return -1;
	}

	for (i = 0; i < count; ++i) {
		ret = __recv_pkt(fd, &pkt[i]);
		if (ret < 0) {
			_E("Failed to receive packet");
			break;
		}
	}

	for (i = 0; i < count; ++i) {
		callback(pkt[i], user_data);
		free(pkt[i]);
	}

	free(pkt);
	close(fd);

	return ret;
}

API int aul_sock_recv_result_with_fd(int fd)
{
	int len;
	int res;

	len = __recv_raw(fd, (unsigned char *)&res, sizeof(int));
	if (len < 0) {
		_E("Failed to receive the result. fd(%d)", fd);
		res = -ECOMM;
	}

	return res;
}

static void __delete_dir(const char *path)
{
	DIR *dp;
	struct dirent *dentry = NULL;
	char buf[PATH_MAX];
	struct stat statbuf;
	int ret;

	if (path == NULL)
		return;

	dp = opendir(path);
	if (dp == NULL)
		return;

	while ((dentry = readdir(dp)) != NULL) {
		if (!strcmp(dentry->d_name, ".") ||
				!strcmp(dentry->d_name, ".."))
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", path, dentry->d_name);
		ret = stat(buf, &statbuf);
		if (ret == 0) {
			if (S_ISDIR(statbuf.st_mode))
				__delete_dir(buf);
			else
				unlink(buf);
		}
	}

	rmdir(path);
	closedir(dp);
}

API int aul_sock_destroy_server(int fd)
{
	char path[PATH_MAX];

	if (fd > 3)
		close(fd);

	if (getuid() >= REGULAR_UID_MIN) {
		snprintf(path, sizeof(path),
				"/run/aul/apps/%u/%d",
				getuid(), getpid());
		__delete_dir(path);
	} else {
		snprintf(path, sizeof(path),
				"/run/aul/daemons/%u/.app-sock-%d",
				getuid(), getpid());
		unlink(path);
	}

	return 0;
}

API int aul_sock_send_result(int fd, int res)
{
	int r;

	if (fd < 0) {
		_E("Invalid parameter");
		return -EINVAL;
	}

	r = send(fd, &res, sizeof(res), MSG_NOSIGNAL);
	if (r < 0) {
		_E("Failed to send result. fd(%d), errno(%d)",
				fd, errno);
		if (errno == EPIPE) {
			_E("EPIPE error");
			close(fd);
			return r;
		}
	}
	close(fd);

	return 0;
}
