#ifndef __DSPMW_DESC_CONF_BASE_H__
#define __DSPMW_DESC_CONF_BASE_H__

class TCBaseDesc;

class TCDescConfBase
{
public :
		TCDescConfBase() {}
	virtual ~TCDescConfBase() {}

	virtual TCBaseDesc* NewDescriptor(int tag,
	                                  const unsigned char* pData,
	                                  unsigned long pds) = 0;

protected :
	virtual TCBaseDesc* t_ProcessPrivateDesc(int tag);
};



#endif /* __DSPMW_DESC_CONF_BASE_H__ */

