/******************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

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
	PMTInstance(ts_pid_t pid);
	virtual ~PMTInstance();

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
