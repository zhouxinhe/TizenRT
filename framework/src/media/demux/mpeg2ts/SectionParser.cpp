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

#include "Mpeg2TsTypes.h"
#include "Section.h"
#include "BaseSection.h"
#include "SectionParser.h"

// Section Info macros
#define TABILE_ID(buffer)                   (buffer[0])
#define SECTION_SYNTAX_INDICATOR(buffer)    ((buffer[1] >> 7) & 1)
#define PRIVATE_INDICATOR(buffer)           ((buffer[1] >> 6) & 1)
#define SECTION_LENGTH(buffer)              (((buffer[1] & 0x0F) << 8) + buffer[2])
#define SI_TSID(buffer)                     ((buffer[3] << 8) + buffer[4])
#define SI_VN(buffer)                       ((buffer[5] >> 1) & 0x1F)
#define SI_CNI(buffer)                      (buffer[5] & 0x01)
#define SI_SN(buffer)                       (buffer[6])
#define SI_LSN(buffer)                      (buffer[7])
#define SI_CRC(buffer,len)                  ((buffer[(len) - 4] << 24) + \
											(buffer[(len) - 3] << 16) + \
											(buffer[(len) - 2] << 8) + \
											(buffer[(len) - 1]))
#define PSI_DATA(buffer)                    (&(buffer[8])) // 8 = SECTION_HEADER_LENGTH + LONG_FORM_HEADER_LENGTH
#define SHORT_FORM(buffer)                  (&(buffer[3]))


#if 0
#define SI_RSV1(buffer)      ((buffer[1]>>4)&0x03)
#define SI_TIDE(buffer)      ((buffer[3]<<8)+buffer[4])

#define SI_PN(buffer)        ((buffer[3]<<8)+buffer[4])
#define SI_SID(buffer)       ((buffer[3]<<8)+buffer[4])
#define SI_RR(buffer)        (buffer[4])
#define SI_RSV2(buffer)      ((buffer[5]>>6)&0x03)// si codereview 070725
#define SI_CNI(buffer)       (buffer[5]&0x01)
#define SI_SN(buffer)        (buffer[6])
#define SI_LSN(buffer)       (buffer[7])
#define PSIP_PV(buffer)        (buffer[8])
#define PSIP_DATA(buffer)      (&(buffer[9]))
#define SHORT_FORM(buffer)		(&(buffer[3]))
#define LONG_FORM(buffer)		(&(buffer[9]))
//==================================================================
#endif

SectionParser::SectionParser(table_id_t tableId)
{
	t_bRecv = false;
	t_pSectionData = nullptr;

	t_pid = INVALID_PID;
	t_tableId = tableId;
	t_sectionSyntaxIndicator = false;
	t_privateIndicator = false;
	t_sectionLength = 0;

	t_tableIdExtension = 0;
	t_versionNumber = 0;
	t_currentNextIndicator = 0;
	t_sectionNumber = 0;
	t_lastSectionNumber = 0;
	t_protocolVersion = 0;
	t_crc = 0;
}

SectionParser::~SectionParser()
{
}

void SectionParser::Initialize(void)
{
	t_Initialize();

	t_bRecv = false;
	t_pSectionData = nullptr;
	t_sectionLength = 0;
}

bool SectionParser::Parse(ts_pid_t pid, uint8_t *pData)
{
	t_bRecv                  = true;
	t_pid                    = pid;
	t_pSectionData           = pData;
	t_tableId                = TABILE_ID(pData);
	t_sectionSyntaxIndicator = SECTION_SYNTAX_INDICATOR(pData);
	t_privateIndicator       = PRIVATE_INDICATOR(pData);
	t_sectionLength          = SECTION_LENGTH(pData);

	printf("[%s] table id: 0x%02x\n", __FUNCTION__, t_tableId);

	if (t_sectionSyntaxIndicator) {
		//Long form
		t_tableIdExtension     = SI_TSID(pData);
		t_versionNumber        = SI_VN(pData);
		t_currentNextIndicator = SI_CNI(pData);
		t_sectionNumber        = SI_SN(pData);
		t_lastSectionNumber    = SI_LSN(pData);
		t_crc                  = SI_CRC(pData,t_sectionLength + SECTION_HEADER_LENGTH);
		return t_Parse(PSI_DATA(pData), t_sectionLength - SectionParser::LONG_FORM_HEADER_LENGTH);
	} else {
		//short form
		return t_Parse(SHORT_FORM(pData), t_sectionLength);
	}
}
