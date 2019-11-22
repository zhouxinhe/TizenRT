#ifndef __VCONF_H__
#define __VCONF_H__

#include <stdbool.h>
// #include <preference/preference.h>
#include "vconf-internal-keys.h"

// #include "error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VCONF_OK                     0
#define VCONF_ERROR                 -1
#define VCONF_ERROR_WRONG_PREFIX    -2
#define VCONF_ERROR_WRONG_TYPE      -3
#define VCONF_ERROR_WRONG_VALUE     -4
#define VCONF_ERROR_NOT_INITIALIZED -5
#define VCONF_ERROR_NO_MEM          -6
#define VCONF_ERROR_FILE_PERM       -11
#define VCONF_ERROR_FILE_BUSY       -12
#define VCONF_ERROR_FILE_NO_MEM     -13
#define VCONF_ERROR_FILE_NO_ENT     -14
#define VCONF_ERROR_FILE_OPEN       -21
#define VCONF_ERROR_FILE_FREAD      -22
#define VCONF_ERROR_FILE_FGETS      -23
#define VCONF_ERROR_FILE_WRITE      -24
#define VCONF_ERROR_FILE_SYNC       -25
#define VCONF_ERROR_FILE_CLOSE      -26
#define VCONF_ERROR_FILE_ACCESS     -27
#define VCONF_ERROR_FILE_CHMOD      -28
#define VCONF_ERROR_FILE_LOCK       -29
#define VCONF_ERROR_FILE_REMOVE     -30
#define VCONF_ERROR_FILE_SEEK       -31
#define VCONF_ERROR_FILE_TRUNCATE   -32
#define VCONF_ERROR_NOT_SUPPORTED   -33

int vconf_set_int(const char *key, int value);
int vconf_set_bool(const char *key, bool value);
int vconf_set_double(const char *key, double value);
int vconf_set_str(const char *key, char *value);
int vconf_get_int(const char *key, int *value);
int vconf_get_bool(const char *key, bool *value);
int vconf_get_double(const char *key, double *value);
char* vconf_get_str(const char *key);
int vconf_unset(const char *key);

#ifdef __cplusplus
}
#endif

#endif
