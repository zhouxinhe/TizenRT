#ifndef __DSPMW_DESCRIPTOR_DVB_H__
#define __DSPMW_DESCRIPTOR_DVB_H__

//#include "DescriptorBase.h"
#include "DescriptorBase.h"

class TCDescriptorDVB : public TCDescriptorBase
{
public :
	enum
	{
		PRIVATE_DESC_START_TAG	= 0x80,
		PRIVATE_DESC_END_TAG		= 0xFF,
	};

private :
	unsigned long m_currPDS;

public :
	//! Constructor
	TCDescriptorDVB();
	//! Destructor
	virtual ~TCDescriptorDVB();

protected:
	virtual TCDescConfBase*	t_GetDescConf(unsigned char tableId);
	virtual void				t_InitParse(void);
	virtual bool				t_CheckAddingDesc(int tag,unsigned char* pData,unsigned long& outPds);
	virtual bool t_checkContentDescriptor(TCBaseDesc* desc, unsigned long curr_pds);
	virtual bool t_CheckLinkageDescriptor( TCBaseDesc* pDesc, unsigned long currPds );

};



#endif /* __DSPMW_DESCRIPTOR_DVB_H__ */
