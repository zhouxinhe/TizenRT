#ifndef __PMT_INSTANCE_H__
#define __PMT_INSTANCE_H__

#include <vector>
#include "Mpeg2TsTypes.h"
#include "BaseSection.h"


class PMTElementary;

class PMTInstance : public BaseSection
{
private:
	ts_pid_t m_pid;
	prog_num_t m_programNumber;
	int8_t m_versionNumber;
	bool m_currentNextIndicator;
	uint8_t m_sectionNumber;
	uint8_t m_lastSectionNumber;
	ts_pid_t m_pcrPID;
	uint16_t m_programInfoLength;
	std::vector<PMTElementary *> m_streamList;

	bool m_Parse(uint8_t *pData, uint32_t size);

public:
	PMTInstance();
	virtual ~PMTInstance();

	bool Create(ts_pid_t PID);
	bool Parse(uint8_t *pData, uint32_t size, prog_num_t programNum, int8_t  versionNumber, uint8_t sectionNumber, uint8_t lastSectionNumber, uint32_t crc32, bool currentNextIndicator);
	void DeleteAll(void);

	size_t NumOfElementary(void);
	PMTElementary *GetPMTElementary(uint32_t index);
	// getters
	ts_pid_t PCR_PID(void) { return m_pcrPID; }
	ts_pid_t PID(void) { return m_pid; }
	prog_num_t ProgramNumber(void) { return m_programNumber; }
	int8_t VersionNumber(void) { return m_versionNumber; }
	bool CurrentNextIndicator(void) { return m_currentNextIndicator; }
	uint8_t SectionNumber(void) { return m_sectionNumber; }
	uint8_t LastSectionNumber(void) { return m_lastSectionNumber; }
	uint16_t ProgramInfoLength(void) { return m_programInfoLength; }
};

#endif /* __PMT_INSTANCE_H__ */
