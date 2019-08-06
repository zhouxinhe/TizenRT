#ifndef __BASE_SECTION_H__
#define __BASE_SECTION_H__

#include "Mpeg2TsTypes.h"

class Section;

class BaseSection
{
public:
	enum {
		TABLE_PRESENT, // section is present (already received)
		TABLE_INITIAL, // receive any section for init table first time
		TABLE_APPEND,  // receive more sections
		TABLE_CHANGE,  // table version changed
		TABLE_IGNORE,  // ignore section, e.g. crc32 verify failed
	};

private:
	// version
	uint8_t m_version;
	// last section number
	uint8_t m_lastSectionNumber;
	// CRC32 value of each section
	uint32_t *m_multiSectionCRC;
	// flag value (received or not) of each section
	bool *m_multiSectionFlag;

protected :
	BaseSection();
	virtual ~BaseSection();
	// check if version changed
	int  t_CheckVersion(uint8_t version, uint8_t sectionNum, uint8_t lastSectionNum, uint32_t crc32 = (uint32_t)INFINITY);
	// Init section
	bool t_InitSection(uint8_t version, uint8_t sectionNumber, uint8_t lastSectionNumber = 0, uint32_t crc32 = (uint32_t)INFINITY);
	// Check if table has been updated.
	bool t_CheckChangeTable(uint8_t version, uint8_t sectionNum, uint8_t lastSectionNum, uint32_t crc32);

public:
	// Is table finished (all sections received)
	bool IsValid(void);
	// Init(Release) section resources
	void InitSection(void);
	// Deletes all of the dynamic memory
	virtual void DeleteAll(void) = 0;
};

#endif /* __BASE_SECTION_H__ */
