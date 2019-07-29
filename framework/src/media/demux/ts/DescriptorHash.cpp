
#include "DescriptorHash.h"
#include "BaseDesc.h"
//#include "OSAbstraction.h"
#include "DTVmwType.h"
//#include "DescExtension.h"
//#include "DescLinkage.h"
//#include "DescContent.h"
//#include "MW.h"
#include "Descriptor.h"

//#include <algorithm>
//#include <stl_utils.h>

//#include "MarshalTreeFormatter.h"
//#include "MarshalClassFormatter.h"

bool
TCDescriptorHash::Create(int num)
{
    return true;
}

bool
TCDescriptorHash::FlagCreate(void)
{
    return true;
}

void
TCDescriptorHash::Destroy(void)
{
    DeleteAll();
}

void
TCDescriptorHash::DeleteAll(void)
{
    std::map<int, std::vector<TCBaseDesc*> >::iterator it;
    std::vector<TCBaseDesc*>::iterator iter;
    it = m_hash.begin();
    while(it != m_hash.end())
    {
        //std::for_each(it->second.begin(), it->second.end(), std::del_fun<TCBaseDesc>());
        iter = it->second.begin();
        for (iter = it->second.begin(); iter != it->second.end(); ++iter)
        {
            delete *iter;
        }
        it->second.clear();

        ++it;
    }
    m_hash.clear();
    m_list.clear();
}

void
TCDescriptorHash::Add(TCBaseDesc* desc)
{
    // Add to both our hash (map->vector)...
    m_hash[desc->Tag()].push_back(desc);
    // ... and to our simple list.
    m_list.push_back(desc);
}

int
TCDescriptorHash::NumOfDescriptors(void)
{
    return m_list.size();
}

TCBaseDesc*
TCDescriptorHash::DescriptorByIndex(int index)
{
    if((unsigned int)index >= m_list.size())
    {
        return NULL;
    }

    return m_list[index];
}

unsigned int
TCDescriptorHash::NumOfDescriptors(int tag)
{
    auto it = m_hash.find(tag);
    if (it == m_hash.end()) {
        return 0;
    }

    return m_hash[tag].size();
}

TCBaseDesc*
TCDescriptorHash::Descriptor(int tag, int index)
{
    auto it = m_hash.find(tag);
    if(it == m_hash.end()) {
        return NULL;
    }

    if ((unsigned int)index >= m_hash[tag].size()) {
        return NULL;
    }

    return m_hash[tag][index];
}

bool
TCDescriptorHash::GetDescriptor(PCList* pDesc)
{
	INT_ASSERT(pDesc);

    if(m_list.empty())
    {
        return false;
    }

    for(unsigned int ii = 0; ii < m_list.size(); ++ii)
    {
        pDesc->push_back(m_list[ii]->Fork());
    }

	return true;
}

TCDescriptorHash&
TCDescriptorHash::operator=(const TCDescriptorHash& desc)
{
    for(unsigned int ii = 0; ii < desc.m_list.size(); ++ii)
    {
        Add(desc.m_list[ii]->Fork());
    }

	return *this;
}
