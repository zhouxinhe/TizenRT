#include "HashInt.h"
#include "DescriptorBase.h"
#include "Descriptor.h"
#include "DescriptorDVB.h"

#define INT_CHECK_INSTANCE    if(m_pImp == NULL)    \
                                return 0;

TCDescriptor::TCDescriptor() : m_pImp(0)
{
	m_pImp = new TCDescriptorDVB();
}

TCDescriptor::~TCDescriptor()
{
    ASSERT(m_pImp);
    delete m_pImp;
    m_pImp = NULL;
}

int
TCDescriptor::Parse(unsigned char* data, int size, TCDescriptorHash& descList,
                    unsigned char tableId)
{
    INT_CHECK_INSTANCE;
    return m_pImp->Parse(data, size, descList,tableId);
}

int
TCDescriptor::ParseByCount(unsigned char* data, int count,
                           TCDescriptorHash& descList, unsigned char tableId)
{
    INT_CHECK_INSTANCE;
    return m_pImp->ParseByCount(data, count, descList,tableId);
}

bool TCDescriptor::SetCachedPDSD(unsigned long pdsd)
{
	INT_CHECK_INSTANCE;
	return m_pImp->SetCachedPDSD(pdsd);
}

