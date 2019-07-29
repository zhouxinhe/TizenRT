
#include "DescriptorBase.h"
#include "DescConfBase.h"
#include "BaseDesc.h"
#include "DescDefault.h"
#include "DescriptorHash.h"
#include "DTVmwType.h"


//------------------------------------------------------------------
#define DESCRIPTOR_TAG(BUFFER)     (BUFFER[0])
#define DESCRIPTOR_LENGTH(BUFFER)  (BUFFER[1])
#define DESCRIPTOR_DATA(BUFFER)    (&(BUFFER[2]))
#define DESCRIPTOR_TAG_AND_LENGTH_NUM_OF_BYTE 2

TCDescriptorBase::TCDescriptorBase() : m_cachedPDSD(INVALID)
{
}

TCDescriptorBase::~TCDescriptorBase()
{
}

int
TCDescriptorBase::Parse(unsigned char* pData, int size, TCDescriptorHash& descList, unsigned char tableId)
{
	int retSize = 0;	// Total length of Descriptor that is parsed.
	int length  = 0;

	t_InitParse();

	TCDescConfBase* pDescConf = t_GetDescConf(tableId);
	if (pDescConf == NULL)
	{
		return retSize;
	}

	while (size > retSize)
	{
		int tag = DESCRIPTOR_TAG(pData);
		int LenOfDescToParse = DESCRIPTOR_LENGTH(pData) + DESCRIPTOR_TAG_AND_LENGTH_NUM_OF_BYTE;	// The length of next descriptor that will be parsed.
		unsigned long outPds = (unsigned long)INVALID;
		bool bAddDesc = t_CheckAddingDesc(tag,pData,outPds);

		if (bAddDesc == false)
		{
			retSize  += LenOfDescToParse;
			pData    += LenOfDescToParse;
			continue;
		}

		TCBaseDesc* desc = pDescConf->NewDescriptor(tag,pData,outPds);

		if (desc == NULL)
		{
			retSize  += LenOfDescToParse;
			pData    += LenOfDescToParse;
			continue;
		}

		if(size < retSize + LenOfDescToParse)
		{
			retSize  += LenOfDescToParse;
			pData    += LenOfDescToParse;
			delete desc;
			desc = NULL;
			continue;
		}

		length = desc->Parse(pData);
		desc->SetTableId(tableId);

		if(m_cachedPDSD != (unsigned long)INVALID)
		{
			outPds = m_cachedPDSD;
		}

		if (length >= DESCRIPTOR_TAG_AND_LENGTH_NUM_OF_BYTE
			&& t_checkContentDescriptor(desc, outPds)
			&& t_CheckLinkageDescriptor( desc, outPds ) )
		{
			descList.Add(desc);
		}
		else
		{
			delete desc;
			desc = NULL;
		}

		retSize += length;
		pData   += length;

	}

	delete pDescConf;
	pDescConf = NULL;

	if(retSize != size)
	{
		BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::MAJOR, "[Warning] TCDescriptorBase::Parse total len is not correct!inLen=%d, outLen=%d", size, retSize);
	}

	return size;
}

int
TCDescriptorBase::ParseByCount(unsigned char* pData, int count,
                               TCDescriptorHash& descList,
                               unsigned char tableId)
{
	int retSize = 0;
	int length  = 0;

	TCDescConfBase* pDescConf  = t_GetDescConf(tableId);

	if (pDescConf == NULL)
	{
		return retSize;
	}

	while (count--)
	{
		TCBaseDesc* desc = pDescConf ->NewDescriptor(DESCRIPTOR_TAG(pData),pData,0);

		if (desc == NULL)
		{
			//defualt Descriptor
			desc = new TCDescDefault(DESCRIPTOR_TAG(pData));// //sicodereview 2007.7.4
			if (desc == NULL)
			{
				retSize  += DESCRIPTOR_LENGTH(pData) + DESCRIPTOR_TAG_AND_LENGTH_NUM_OF_BYTE;
				pData    += DESCRIPTOR_LENGTH(pData) + DESCRIPTOR_TAG_AND_LENGTH_NUM_OF_BYTE;
				continue;
			}
		}

		descList.Add(desc);

		length = desc->Parse(pData);
		desc->SetTableId(tableId);

		retSize += length;
		pData   += length;
	}

	delete pDescConf;
	pDescConf = NULL;

	return retSize;
}

void TCDescriptorBase::t_InitParse(void)
{
	return ;
}

bool
TCDescriptorBase::t_CheckAddingDesc(int tag, unsigned char* pData,
                                    unsigned long& outPds)
{
	return true;
}


