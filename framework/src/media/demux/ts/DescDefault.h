#ifndef __DSPMW_DESC_STUFFING_H__
#define __DSPMW_DESC_STUFFING_H__

#include "BaseDesc.h"

//! Stuffing Descriptor class
class TCDescDefault : public TCBaseDesc
{
protected:

	//! data�� �Ľ�
	virtual int t_Parse(unsigned char* data, unsigned char len);

public:

	//! Constructor
	TCDescDefault(int tag);
	virtual ~TCDescDefault(void);

	//! Deletes all of the dynamic memory
	virtual void        DeleteAll(void);
	//! �� Ŭ������ ������ Ŭ������ �����ϰ�, �� �ּҸ� ��ȯ
	virtual TCBaseDesc* Fork(void);

};

#endif /* __DSPMW_DESC_STUFFING_H__ */

