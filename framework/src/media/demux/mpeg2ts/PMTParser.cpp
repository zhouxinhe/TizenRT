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


#include "Section.h"
#include "PMTParser.h"
#include "PMTInstance.h"


PMTParser::PMTParser() : SectionParser(TABLE_ID)
{
	m_programNumber = (prog_num_t)INFINITY;
}

PMTParser::~PMTParser()
{
	Initialize();
}

void PMTParser::t_Initialize(void)
{
	m_programNumber = (prog_num_t)INFINITY;

	auto it = m_PmtInstances.begin();
	while (it != m_PmtInstances.end()) {
		delete it->second;
		++it;
	}
	m_PmtInstances.clear();
	m_PMTElements.clear();
}

bool PMTParser::t_Parse(uint8_t *pData, uint32_t size)
{
	m_programNumber = (prog_num_t)INFINITY;

	if (!m_PMTElements.empty()) {
		auto it = m_PMTElements.find(makeKey(t_pid, t_tableIdExtension));
		if (it == m_PMTElements.end()) {
			return false;
		}
	}

	// table id extension filed is the program nubmer in PMT
	m_programNumber = t_tableIdExtension;

	PMTInstance *pInstance = m_PmtInstances[m_programNumber];
	if (pInstance == NULL) {
		pInstance = new PMTInstance(t_pid);
		assert(pInstance);
		// add PMT instance
		m_PmtInstances[m_programNumber] = pInstance;
		medvdbg("add pmt instance: programnumber %d, pid 0x%x\n", m_programNumber, t_pid);
	}

	return pInstance->Parse(pData, size, t_tableIdExtension, t_versionNumber,
							t_sectionNumber, t_lastSectionNumber,t_crc, t_currentNextIndicator);
}

prog_num_t PMTParser::ProgramNumber(void)
{
	return m_programNumber;
}

size_t PMTParser::NumOfPMTInstance(void)
{
	return m_PmtInstances.size();
}

PMTInstance *PMTParser::GetPMTInstance(prog_num_t programNumber)
{
	auto it = m_PmtInstances.find(programNumber);
	if (it != m_PmtInstances.end()) {
		return it->second;
	}

	return nullptr;
}

PMTInstance *PMTParser::PMTInstanceOfIndex(uint32_t index)
{
	auto it = m_PmtInstances.begin();
	uint32_t curr = 0;
	while (it != m_PmtInstances.end()) {
		if (curr++ == index) {
			break;
		}
		it++;
	}

	if (it != m_PmtInstances.end()) {
		return it->second;
	}

	return nullptr;
}

void PMTParser::UpdatePMTElements(std::map<int, ts_pid_t> &pmtMap)
{
	m_PMTElements = pmtMap;
}

void PMTParser::ClearPMTElements(void)
{
	m_PMTElements.clear();
}

int PMTParser::makeKey(ts_pid_t pid, prog_num_t progNum)
{
	return ((pid << 16) | progNum);
}
