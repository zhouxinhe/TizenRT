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

#ifndef __SECTION_PARSER_H__
#define __SECTION_PARSER_H__

#include <vector>

class Section;

class SectionParser
{
public:
	enum {
		PAT_PID = 0x0000,
	};

	enum {
		SECTION_HEADER_LENGTH = 3,
		LONG_FORM_HEADER_LENGTH = 5,
		SECTION_MAX_LENGTH = 4096,
	};

public:
	virtual ~SectionParser();
	// Initialize parser
	virtual void Initialize(void);
	// Parse section data
	virtual bool Parse(ts_pid_t PID, uint8_t *pData);
	// getters
	virtual bool IsRecv(void) { return t_bRecv; }
	virtual ts_pid_t Pid(void) { return t_pid; }
	virtual table_id_t TableId(void) { return t_tableId; }
	virtual uint16_t TableIdExt(void) { return t_tableIdExtension; }
	virtual uint8_t SectionSyntaxIndicator(void) { return t_sectionSyntaxIndicator; }
	virtual uint8_t PrivateIndicator(void) { return t_privateIndicator; }
	virtual uint16_t SectionLength(void) { return t_sectionLength; }
	virtual int8_t VersionNumber(void) { return t_versionNumber; }
	virtual int8_t CurrentNextIndicator(void) { return t_currentNextIndicator; }
	virtual uint8_t SectionNumber(void) { return t_sectionNumber; }
	virtual uint8_t LastSectionNumber(void) { return t_lastSectionNumber; }
	virtual uint32_t SectionCRC(void) { return t_crc; }

protected:
	SectionParser(table_id_t tableId);
	// section parsing method, derived class should implement it
	virtual bool t_Parse(uint8_t *pData, uint32_t size) = 0;
	// Initialize method, derived class should implement it
	virtual void t_Initialize(void) = 0;

protected:
	bool t_bRecv;
	uint8_t *t_pSectionData;

	// section_pid
	ts_pid_t t_pid;
	// table_id
	table_id_t t_tableId;
	// section_syntax_indicatior
	bool t_sectionSyntaxIndicator;
	// private_indicatior
	bool t_privateIndicator;
	// section_length
	uint16_t t_sectionLength;
	// table_id_extention
	uint16_t  t_tableIdExtension;
	// version_number
	int8_t t_versionNumber;
	// current_next_indicator
	bool t_currentNextIndicator;
	// section_number
	uint8_t t_sectionNumber;
	// last_section_number
	uint8_t t_lastSectionNumber;
	// protocal_version
	uint8_t t_protocolVersion;
	// crc32
	uint32_t t_crc;
};

#endif /* __SECTION_PARSER_H__ */
