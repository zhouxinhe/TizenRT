#ifndef __DSPMW_PMT_ITEM_H__
#define __DSPMW_PMT_ITEM_H__

#include "DTVmwType.h"
#include "BaseSection.h"
#include "DescriptorHash.h"

class TCPMTElementary;

//! The class for parsing the PMT packet
class TCPMTInstance : public TCBaseSection , public IDescriptorContainer
{
private:

	TTPID          m_pid;
	//! program_number
	TTPN m_programNumber;
	//! version_number
	char           m_versionNumber;
	//! current_next_indicator
	bool           m_currentNextIndicator;
	//! section_number
	unsigned char  m_sectionNumber;
	//! last_section_number
	unsigned char  m_lastSectionNumber;
	//! PCR_PID
	TTPID m_pcrPID;

	short          m_programInfoLength;

	//! The list of the stream
	PCList    m_streamList;
	//! The hash table of the descriptor
	TCDescriptorHash m_descriptorHash;
	//! Parses the packet
	bool m_Parse(unsigned char* pData, int size);
public:

	TCPMTInstance();
	virtual ~TCPMTInstance();

	bool Create(TTPID PID);
	bool Parse(unsigned char* pData, int size, TTPN programNum, char  versionNumber, unsigned char sectionNumber, unsigned char lastSectionNumber,unsigned long crc32, bool currentNextIndicator);
	void DeleteAll(void);

	int              NumOfElementary(void);
	TCPMTElementary* PMTElementary(int idx);

	TTPID             PCR_PID(void);

	//! Program PID�� ��ȯȯ��.
	TTPID            PID(void)                  { return m_pid;}
	//! Program Number�� ��ȯ�Ѵ�.
	TTPN  ProgramNumber(void)        { return m_programNumber;}
	//! Version Number�� ��ȯ�Ѵ�.
	char             VersionNumber(void)        { return m_versionNumber;}
	//! Current Next Indicator�� ��ȯ�Ѵ�.
	bool			 CurrentNextIndicator(void) { return m_currentNextIndicator;}
	//! Section Number�� ��ȯ�Ѵ�.
	unsigned char    SectionNumber(void)        {return m_sectionNumber;}
	//! Last Section Number�� ��ȯ�Ѵ�.
	unsigned char    LastSectionNumber(void)    { return m_lastSectionNumber;}
	//! Program Info Length�� ��ȯ�Ѵ�(Outer Descriptor�� ����).
	short            ProgramInfoLength(void)    { return m_programInfoLength; }

#if 1
    /// @name API interface from IDescriptorContainer.  This class provides the
    /// IDescriptorContainer API.  Any class that uses this class can then
    /// also derive from IDescriptorContainer to provide a consistent API for
    /// accessing stored descriptors.
    /// @{
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
    /// @}
#endif
};




#endif /* __DSPMW_PMT_ITEM_H__ */

