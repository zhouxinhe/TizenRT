#ifndef __BASE_SECTION_H__
#define __BASE_SECTION_H__

#include "DTVmwType.h"

class Section;
class TCBaseSection
{
public:
	enum {
		TABLE_PRESENT,
		TABLE_INITIAL,
		TABLE_APPEND,
		TABLE_CHANGE,
		TABLE_IGNORE,
	};

private:
	int m_lastSectionNumber;
	uint32_t *m_multiSectionCRC;

    int m_multiSectionNumber;
    int m_checkSectionNumber;
    int m_checkVersionResult;

protected :
	// multi section flag
	bool *t_multiSectionFlag;
    // section data
    Section **m_multiSection;
	//! version
	int m_version;

    TCBaseSection();
	virtual ~TCBaseSection();

	int  t_CheckVersion(int version, int sectionNum, int lastSectionNum, uint32_t crc32 = (uint32_t)INFINITY);
	bool t_InitSection(int sectionNumber, int lastSectionNumber = 0, uint32_t crc32 = (uint32_t)INFINITY);

	//bool t_CheckSegment(int sectionNumber, int lastSectionNumber, int segmentLastSectionNumber);
	bool t_CheckChangeTable(int version, int sectionNum, int lastSectionNum, uint32_t crc32);

public:
	bool IsValid(void);
	void InitSection(void);
	//bool IsRecvSegment(int startSegmentNumber, int EndSegmentNumber);
	int	LastSectionNum(void);
	bool IsRecvSection(int sectionNumber);
	bool RemoveSection(int sectionNumber);

	bool SetSection(int sectionNumber, Section* pSection);
	bool GetSection(int sectionNumber, Section**ppSection);
	bool SaveSection(Section* pSection);

	//! Deletes all of the dynamic memory
	virtual void DeleteAll(void) = 0;
};

#endif /* __BASE_SECTION_H__ */
