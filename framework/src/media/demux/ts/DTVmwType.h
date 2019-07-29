#ifndef	__DSPMW_DTVTYPE_H__
#define __DSPMW_DTVTYPE_H__

#ifndef INFINITY
#define INFINITY ~0
#endif

#define INVALID -1

#define comment
#define PID_INVALID     0x1FFF
#define CONTINUITY_COUNTER_MOD 16

#include <vector>
#define PCList std::vector<void *>
#include <map>
#define TCHashInt std::map<int, void *>

typedef    unsigned short    	TTPN;
typedef    int               	TTTSID;
typedef    short             	TTPID;
typedef    unsigned short    	TTPtc;
typedef    unsigned short    	TTMajor;
typedef    unsigned short    	TTMinor;
typedef    unsigned short    	TTSourceId;
typedef	   unsigned short    	TTProgramNumber;
typedef    unsigned short   	TTLCN;

#include <stdint.h>
#include <stdio.h>
#define BP_PRINT(module, level, format, ...)  printf(format, ##__VA_ARGS__)
#include <assert.h>
#define P_ASSERT(expr) assert(expr)
#if 1
// ==============================================================================
//CCDebugBP::PrintBuffer();
#ifndef INT_ASSERT
#define INT_ASSERT(VAL)		\
	{			\
		bool __ret = (VAL) ? true: false;	\
		if(!__ret) 	\
		{		\
			P_ASSERT(VAL);		\
			BP_PRINT( CCDebugBP::DEFAULT, CCDebugBP::FATAL, "ASSERT!, Func:%s", __FUNCTION__);	\
			return 0;	\
		}			\
	}

#endif

#ifndef VOID_ASSERT
#define VOID_ASSERT(VAL)	\
	{			\
		bool __ret = (VAL) ? true: false;	\
		if(!__ret) 	\
		{		\
			P_ASSERT(VAL);		\
			BP_PRINT( CCDebugBP::DEFAULT, CCDebugBP::FATAL, "ASSERT!, Func:%s", __FUNCTION__);	\
			return ;	\
		}			\
	}
#endif

// Return 문이 아예 없어야 하는 경우.
#ifndef ONLY_ASSERT
#define ONLY_ASSERT(VAL)	\
	{			\
		bool __ret = (VAL) ? true: false;	\
		if(!__ret) 	\
		{	\
			P_ASSERT(VAL);		\
			BP_PRINT( CCDebugBP::DEFAULT, CCDebugBP::FATAL, "ASSERT!, Func:%s", __FUNCTION__);	\
		}	\
	}
#endif

#endif


#ifndef DELETE_SORTED_LIST
#define  DELETE_SORTED_LIST(CLASS, VARIABLE)       \
	do { \
		auto it = VARIABLE.begin(); \
		while (it != VARIABLE.end()) { \
			CLASS* obj = (CLASS *)*it; \
			if (obj) { \
				delete obj; \
				*it = NULL; \
			} \
			it++; \
		} \
	} while (0)
#endif

#ifndef DELETE_LIST
#define  DELETE_LIST(CLASS, VARIABLE)    DELETE_SORTED_LIST(CLASS, VARIABLE)
#endif


#endif /* __DSPMW_DTVTYPE_H__ */
