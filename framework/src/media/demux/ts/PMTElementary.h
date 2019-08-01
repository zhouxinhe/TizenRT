#ifndef __DSPMW_PMT_ITEM_STREAM_H__
#define __DSPMW_PMT_ITEM_STREAM_H__

#include "DTVmwType.h"
#include "DescriptorHash.h"

enum EStreamType
{
	STREAM_TYPE_AUDIO_MPEG1 			= 0x03, //Common
	STREAM_TYPE_AUDIO_MPEG2 			= 0x04, //Common
	STREAM_TYPE_AUDIO_AAC				= 0x0F, //Common
	STREAM_TYPE_AUDIO_HE_AAC			= 0x11, //Common
	STREAM_TYPE_AUDIO_AC3				= 0x81, //Common
};

class TCBaseDesc;
class TCPMTElementary : public IDescriptorContainer
{
private :

	//! stream_type
	unsigned char m_streamType;
	//! elementary_PID
	TTPID m_elementary_PID;
    //! ES_info_length
	short m_esInfoLength;
	//! The hash table of the descriptor
	TCDescriptorHash m_descriptorHash;

public:

	TCPMTElementary();
	~TCPMTElementary();
	bool Create(void);
	short ESInfoLength(void) { return m_esInfoLength; }
	unsigned char StreamType(void);
	TTPID ElementaryPID(void);

	int Parse(unsigned char* pData);

    // Override IDescriptorContainer interface
    virtual unsigned int NumOfDescriptors(int tag)
        { return m_descriptorHash.NumOfDescriptors(tag); }

    virtual TCBaseDesc* Descriptor(int tag, int index = 0)
        { return m_descriptorHash.Descriptor(tag, index); }

    virtual int NumOfDescriptors(void)
        { return m_descriptorHash.NumOfDescriptors(); }

    virtual TCBaseDesc* DescriptorByIndex(int index)
        { return m_descriptorHash.DescriptorByIndex(index); }

    virtual bool GetDescriptor(PCList* pDesc)
        { return m_descriptorHash.GetDescriptor(pDesc); }
};

#endif /* __DSPMW_PMT_ITEM_STREAM_H__ */

