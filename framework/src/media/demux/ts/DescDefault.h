#ifndef __DSPMW_DESC_STUFFING_H__
#define __DSPMW_DESC_STUFFING_H__

#include "BaseDesc.h"

//! Stuffing Descriptor class
class TCDescDefault : public TCBaseDesc
{
protected:

	//! data를 파싱
	virtual int t_Parse(unsigned char* data, unsigned char len);

public:

	//! Constructor
	TCDescDefault(int tag);
	virtual ~TCDescDefault(void);

	//! Deletes all of the dynamic memory
	virtual void        DeleteAll(void);
	//! 본 클래스와 동일한 클래스를 생성하고, 그 주소를 반환
	virtual TCBaseDesc* Fork(void);

};

#endif /* __DSPMW_DESC_STUFFING_H__ */

