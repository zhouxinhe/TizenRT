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

#include <debug.h>
#include "Mpeg2TsTypes.h"
#include "PATParser.h"


#define PAT_UNTIL_LAST_SECTION_NUMBER_LEN       (9)
#define PAT_PROG_NUM_PID_LEN                    (4)
#define PAT_PROGRAM_NUMBER(buffer,idx)          ((buffer[4*(idx)]<<8)+(buffer[4*(idx)+1]))
#define PAT_PROGRAM_NUMBER_PID(buffer,idx)      ((((buffer[4*(idx)+2])&0x1F)<<8)+(buffer[4*(idx)+3]))



PATParser::PATParser()
	: SectionParser(TABLE_ID)
{
	m_transportStreamId = 0;
	m_networkPID = INVALID_PID;
}

PATParser::~PATParser()
{
	Initialize();
}

void PATParser::t_Initialize(void)
{
	BaseSection::InitSection();
	DeleteAll();
}

void PATParser::DeleteAll(void)
{
	m_transportStreamId = 0;
	m_networkPID = INVALID_PID;
	m_programMap.clear();
}

bool PATParser::t_Parse(uint8_t *pData, uint32_t size)
{
	switch (t_CheckVersion(t_versionNumber, t_sectionNumber, t_lastSectionNumber, t_crc)) {
	case TABLE_INITIAL:
	case TABLE_CHANGE:
	case TABLE_APPEND: {
		m_transportStreamId = t_tableIdExtension;
		int i;
		for (i = 0; i < ((t_sectionLength - PAT_UNTIL_LAST_SECTION_NUMBER_LEN) / PAT_PROG_NUM_PID_LEN); i++) {
			t_AddProgram(PAT_PROGRAM_NUMBER(pData, i), PAT_PROGRAM_NUMBER_PID(pData, i));
		}
		return IsValid();
	}
	case TABLE_IGNORE :
		medvdbg("PAT Section Ignored...\n");
		break;
	default:
		break;
	}

	return false;
}

size_t PATParser::NumOfProgramList(void)
{
	return m_programMap.size();
}

prog_num_t PATParser::ProgramNumber(uint32_t index)
{
	if (index >= m_programMap.size()) {
		return (prog_num_t)INFINITY;
	}

	uint32_t curr = 0;
	auto it = m_programMap.begin();
	while (it != m_programMap.end()) {
		if (index == curr++) {
			return (prog_num_t)it->first;
		}
		it++;
	}

	return (prog_num_t)INFINITY;
}

ts_pid_t PATParser::ProgramPID(prog_num_t programNumber)
{
	auto it = m_programMap.find(programNumber);
	if (it == m_programMap.end()) {
		meddbg("[ProgramPID] pn %d -> INVALID_PID\n", programNumber);
		return INVALID_PID;
	}

	medvdbg("[ProgramPID] pn %d -> pmt pid 0x%x\n", programNumber, it->second);
	return it->second;
}

void PATParser::t_AddProgram(prog_num_t programNumber, ts_pid_t programPID)
{
	// program number 0x0000 is reserved to specify the network PID
	if (programNumber == PATParser::NETWORK_PID) {
		medvdbg("NIT table pid 0x%04x\n", programPID);
		m_networkPID = programPID;
		return ;
	}

	medvdbg("program %d pid 0x%x\n", programNumber, programPID);
	m_programMap[programNumber] = programPID;
}

stream_id_t PATParser::TansportStreamId(void)
{
	return m_transportStreamId;
}

ts_pid_t PATParser::NetworkPID(void)
{
	return m_networkPID;
}

bool  PATParser::IsRecv(void)
{
	if (SectionParser::IsRecv()) {
		return IsValid();
	}

	return false;
}
