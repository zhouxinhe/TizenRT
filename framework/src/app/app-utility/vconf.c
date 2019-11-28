#include <queue.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

#include <preference/preference.h>

#include "vconf.h"

#define VCONF_DB_PREFIX "db/"
#define VCONF_FILE_PREFIX "file/"
#define VCONF_MEMORY_PREFIX "memory/"

enum vconf_storage_type_e {
	VCONF_STORAGE_DB = 0,
	VCONF_STORAGE_FILE = 1,
	VCONF_STORAGE_MEMORY = 2,
};

enum vconf_data_type_e {
	VCONF_DATA_INT = 0,
	VCONF_DATA_BOOL = 1,
	VCONF_DATA_DOUBLE = 2,
	VCONF_DATA_STRING = 3,
	VCONF_DATA_TYPE_MAX = 4,
};

struct vconf_data_s {
	int type;
	union {
		int i;
		bool b;
		double d;
		char *s;
	} value;
};
typedef struct vconf_data_s vconf_data_t;

struct vconf_keynode_s {
	struct vconf_keynode_s *flink;
	char *keyname;
	vconf_data_t data;
};
typedef struct vconf_keynode_s vconf_keynode_t;

sq_queue_t vconf_mem_key_list;

/*
* The vconf keys have specific scheme like below,
* "db/private/org.tizen.vc-engine-bixby/audio_format", "memory/private/bixby/state"
*/

/****************************************************************************
 * Private Functions
 ****************************************************************************/
static int vconf_get_type(const char *key)
{
	int ret = ERROR;
	if (strncmp(key, VCONF_DB_PREFIX, (sizeof(VCONF_DB_PREFIX)-1)) == 0) {
		ret = VCONF_STORAGE_DB;
	} else if (strncmp(key, VCONF_FILE_PREFIX, (sizeof(VCONF_FILE_PREFIX)-1)) == 0) {
		ret = VCONF_STORAGE_FILE;
	} else if (strncmp(key, VCONF_MEMORY_PREFIX, (sizeof(VCONF_MEMORY_PREFIX)-1)) == 0) {
		ret = VCONF_STORAGE_MEMORY;
	}

	return ret;
}

static vconf_keynode_t *vconf_mem_find_key(char *key)
{
	vconf_keynode_t *ptr;

	if (key == NULL) {
		printf("[vconf] Invalid parameter\n");
		return NULL;
	}

	ptr = (vconf_keynode_t *)sq_peek(&vconf_mem_key_list);
	while (ptr != NULL) {
		// [TODO] Expensive string comparision. optimize this logic later.
		if (strncmp(key, ptr->keyname, strlen(ptr->keyname) + 1) == 0) {
			return ptr;
		}
		ptr = (vconf_keynode_t *)sq_next(ptr);
	}

	return ptr;
}

static int vconf_mem_write(char *key, vconf_data_t *data)
{
	vconf_keynode_t *keynode;

	if (key == NULL || data == NULL) {
		printf("[vconf] Invalid parameter\n");
		return VCONF_ERROR;
	}

	if (data->type < 0 || data->type >= VCONF_DATA_TYPE_MAX) {
		printf("[vconf] Invalid type\n");
		return VCONF_ERROR_WRONG_TYPE;
	}

	/* Search and update value if it is already exist. */
	keynode = vconf_mem_find_key(key);
	if (keynode != NULL) {
		if (data->type != keynode->data.type) {
			return VCONF_ERROR_WRONG_TYPE;
		}
		if (data->type == VCONF_DATA_STRING) {
			free(keynode->data.value.s);
			keynode->data.value.s = (char *)strndup(data->value.s, strlen(data->value.s) + 1);
		} else {
			keynode->data.value.d = data->value.d;
		}
		return VCONF_OK;
	}

	/* Allocate a new keynode */
	keynode = (vconf_keynode_t *)malloc(sizeof(vconf_keynode_t));
	if (keynode == NULL) {
		return VCONF_ERROR_NO_MEM;
	}

	/* Set key data and Add keynode to keynode list */
	keynode->flink = NULL;
	keynode->keyname = (char *)strndup(key, strlen(key) + 1);
	keynode->data.type = data->type;
	if (keynode->data.type == VCONF_DATA_STRING) {
		keynode->data.value.s = (char *)strndup(data->value.s, strlen(data->value.s) + 1);
	} else {
		keynode->data.value = data->value;
	}
	sq_addfirst((sq_entry_t *)keynode, &vconf_mem_key_list);

	return VCONF_OK;
}

static int vconf_mem_read(char *key, vconf_data_t *data)
{
	vconf_keynode_t *keynode;

	if (key == NULL || data == NULL) {
		printf("[vconf] Invalid parameter\n");
		return VCONF_ERROR;
	}

	keynode = vconf_mem_find_key(key);
	if (keynode == NULL) {
		/* Key is not exist. */
		printf("[vconf] key %s is not exist\n", key);
		return VCONF_ERROR;
	}

	if (data->type != keynode->data.type) {
		return VCONF_ERROR_WRONG_TYPE;
	}
	if (data->type == VCONF_DATA_STRING) {
		data->value.s = (char *)strndup(keynode->data.value.s, strlen(keynode->data.value.s) + 1);
	} else {
		data->value = keynode->data.value;
	}

	return VCONF_OK;
}

static int vconf_mem_remove(char *key)
{
	vconf_keynode_t *keynode;

	if (key == NULL) {
		printf("[vconf] Invalid parameter\n");
		return VCONF_ERROR;
	}

	keynode = vconf_mem_find_key(key);
	if (keynode == NULL) {
		/* Key is not exist. */
		printf("[vconf] key %s is not exist\n", key);
		return VCONF_ERROR;
	}

	/* Remove Key node from key list */
	sq_rem((sq_entry_t *)keynode, (sq_queue_t *)&vconf_mem_key_list);

	free(keynode->keyname);
	if (keynode->data.type == VCONF_DATA_STRING) {
		free(keynode->data.value.s);
	}
	free(keynode);

	return VCONF_OK;
}

static int vconf_fs_write(char *key, vconf_data_t *data)
{
	int ret;

	if (key == NULL || data == NULL) {
		printf("[vconf] Invalid parameter\n");
		return VCONF_ERROR;
	}

	switch (data->type) {
	case VCONF_DATA_INT:
		ret = preference_shared_set_int(key, data->value.i);
		break;
	case VCONF_DATA_BOOL:
		ret = preference_shared_set_bool(key, data->value.b);
		break;
	case VCONF_DATA_DOUBLE:
		ret = preference_shared_set_double(key, data->value.d);
		break;
	case VCONF_DATA_STRING:
		ret = preference_shared_set_string(key, data->value.s);
		break;
	default:
		return VCONF_ERROR_WRONG_TYPE;
	}

	if (ret < 0) {
		/* Match preferecence errno to vconf errno */
		if (ret == PREFERENCE_OUT_OF_MEMORY) {
			ret = VCONF_ERROR_NO_MEM;
		} else {
			ret = VCONF_ERROR;
		}
	}

	return VCONF_OK;
}

static int vconf_fs_read(char *key, vconf_data_t *data)
{
	int ret;

	if (key == NULL || data == NULL) {
		printf("[vconf] Invalid parameter\n");
		return VCONF_ERROR;
	}

	switch (data->type) {
	case VCONF_DATA_INT:
		ret = preference_shared_get_int(key, &data->value.i);
		break;
	case VCONF_DATA_BOOL:
		ret = preference_shared_get_bool(key, &data->value.b);
		break;
	case VCONF_DATA_DOUBLE:
		ret = preference_shared_get_double(key, &data->value.d);
		break;
	case VCONF_DATA_STRING:
		ret = preference_shared_get_string(key, &data->value.s);
		break;
	default:
		return VCONF_ERROR_WRONG_TYPE;
	}

	if (ret < 0) {
		/* Match preferecence errno to vconf errno */
		if (ret == PREFERENCE_OUT_OF_MEMORY) {
			ret = VCONF_ERROR_NO_MEM;
		} else {
			ret = VCONF_ERROR;
		}
	}

	return ret;
}

static int vconf_write(const char *key, vconf_data_t *data)
{
	int ret;
	int type;
	char *key_path;

	ret = VCONF_ERROR;

	if (key == NULL || data == NULL) {
		printf("[vconf] Invalid parameter\n");
		return VCONF_ERROR;
	}

	key_path = (char *)strchr(key, '/');
	if (key_path == NULL) {
		printf("[vconf] Wrong prefix ERROR\n");
		return VCONF_ERROR_WRONG_PREFIX;
	}
	key_path++;

	type = vconf_get_type(key);
	switch (type) {
	case VCONF_STORAGE_DB:
		/* DB storage is not supported, so it uses file instead. */
		printf("DB storage is not supported, so it uses file instead.\n");
	case VCONF_STORAGE_FILE:
		ret = vconf_fs_write(key_path, data);
		break;
	case VCONF_STORAGE_MEMORY:
		ret = vconf_mem_write(key_path, data);
		break;
	default:
		ret = VCONF_ERROR_WRONG_PREFIX;
	}

	return ret;
}

static int vconf_read(const char *key, vconf_data_t *data)
{
	int ret;
	int type;
	char *key_path;

	if (key == NULL || data == NULL) {
		printf("[vconf] Invalid parameter\n");
		return VCONF_ERROR;
	}

	key_path = (char *)strchr(key, '/');
	if (key_path == NULL) {
		printf("[vconf] Wrong prefix ERROR\n");
		return VCONF_ERROR_WRONG_PREFIX;
	}
	key_path++;

	type = vconf_get_type(key);
	switch (type) {
	case VCONF_STORAGE_DB:
		/* DB storage is not supported, so it uses file instead. */
	case VCONF_STORAGE_FILE:
		ret = vconf_fs_read(key_path, data);
		break;
	case VCONF_STORAGE_MEMORY:
		ret = vconf_mem_read(key_path, data);
		break;
	default:
		ret = VCONF_ERROR_WRONG_PREFIX;
	}

	return ret;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/
int vconf_set_int(const char *key, int value)
{
	vconf_data_t data;

	if (key == NULL) {
		printf("[vconf] Invalid parameter\n");
		return VCONF_ERROR;
	}

	data.type = VCONF_DATA_INT;
	data.value.i = value;

	return vconf_write(key, &data);
}

int vconf_set_bool(const char *key, bool value)
{
	vconf_data_t data;

	if (key == NULL) {
		printf("[vconf] Invalid parameter\n");
		return VCONF_ERROR;
	}

	data.type = VCONF_DATA_BOOL;
	data.value.b = value;

	return vconf_write(key, &data);
}


int vconf_set_double(const char *key, double value)
{
	vconf_data_t data;

	if (key == NULL) {
		printf("[vconf] Invalid parameter\n");
		return VCONF_ERROR;
	}

	data.type = VCONF_DATA_DOUBLE;
	data.value.d = value;

	return vconf_write(key, &data);
}


int vconf_set_str(const char *key, char *value)
{
	vconf_data_t data;

	if (key == NULL) {
		printf("[vconf] Invalid parameter\n");
		return VCONF_ERROR;
	}

	data.type = VCONF_DATA_STRING;
	data.value.s = value;

	return vconf_write(key, &data);
}

int vconf_get_int(const char *key, int *value)
{
	int ret;
	vconf_data_t data;

	if (key == NULL) {
		printf("[vconf] Invalid parameter\n");
		return VCONF_ERROR;
	}

	data.type = VCONF_DATA_INT;
	ret = vconf_read(key, &data);
	if (ret == VCONF_OK) {
		*value = data.value.i;
	}

	return ret;
}

int vconf_get_bool(const char *key, bool *value)
{
	int ret;
	vconf_data_t data;

	if (key == NULL) {
		printf("[vconf] Invalid parameter\n");
		return VCONF_ERROR;
	}

	data.type = VCONF_DATA_BOOL;
	ret = vconf_read(key, &data);
	if (ret == VCONF_OK) {
		*value = data.value.b;
	}

	return ret;
}

int vconf_get_double(const char *key, double *value)
{
	int ret;
	vconf_data_t data;

	if (key == NULL) {
		printf("[vconf] Invalid parameter\n");
		return VCONF_ERROR;
	}

	data.type = VCONF_DATA_DOUBLE;
	ret = vconf_read(key, &data);
	if (ret == VCONF_OK) {
		*value = data.value.d;
	}

	return ret;
}

char * vconf_get_str(const char *key)
{
	int ret;
	vconf_data_t data;

	if (key == NULL) {
		printf("[vconf] Invalid parameter\n");
		return NULL;
	}

	data.type = VCONF_DATA_STRING;
	ret = vconf_read(key, &data);
	if (ret == VCONF_OK) {
		return (char *)data.value.s;
	}

	return NULL;
}

int vconf_unset(const char *key)
{
	int ret;
	int type;
	char *key_path;

	ret = VCONF_ERROR;

	if (key == NULL) {
		printf("[vconf] Invalid parameter\n");
		return VCONF_ERROR;
	}

	key_path = (char *)strchr(key, '/');
	if (key_path == NULL) {
		printf("[vconf] Wrong prefix ERROR\n");
		return VCONF_ERROR_WRONG_PREFIX;
	}
	key_path++;

	type = vconf_get_type(key);
	switch (type) {
	case VCONF_STORAGE_DB:
		/* DB storage is not supported, so it uses file instead. */
	case VCONF_STORAGE_FILE:
		ret = preference_shared_remove(key_path);
		break;
	case VCONF_STORAGE_MEMORY:
		ret = vconf_mem_remove(key_path);
		break;
	default:
		ret = VCONF_ERROR_WRONG_PREFIX;
	}

	return ret;
}
