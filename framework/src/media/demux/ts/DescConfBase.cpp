
#include "BaseDesc.h"
#include "DescConfBase.h"
#include "DescDefault.h"

TCBaseDesc* TCDescConfBase::t_ProcessPrivateDesc(int tag)
{
	return new TCDescDefault(tag);
}

