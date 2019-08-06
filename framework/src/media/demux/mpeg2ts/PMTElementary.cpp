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
#include "PMTElementary.h"

#define PMT_ES_BODY_BYTES               (5)
#define PMT_STREAM_TYPE(BUFFER)         (BUFFER[0])
#define PMT_ELEMENTARY_PID(BUFFER)      (((BUFFER[1]&0x1F)<<8)+BUFFER[2])
#define PMT_ES_INFO_LENGTH(BUFFER)      (((BUFFER[3]&0x0F)<<8)+BUFFER[4])

PMTElementary::PMTElementary()
{
	m_elementary_PID = INFINITY;
	m_streamType = 0;
	m_esInfoLength = 0;
}

PMTElementary::~PMTElementary()
{
}

uint8_t PMTElementary::StreamType(void)
{
	return m_streamType;
}

ts_pid_t PMTElementary::ElementaryPID(void)
{
	return m_elementary_PID;
}

int16_t PMTElementary::ESInfoLength(void)
{
	return m_esInfoLength;
}

int32_t PMTElementary::Parse(uint8_t *pData)
{
	m_streamType = PMT_STREAM_TYPE(pData);
	m_elementary_PID = PMT_ELEMENTARY_PID(pData);
	m_esInfoLength = PMT_ES_INFO_LENGTH(pData);

	// currently, ignore ES info descriptors...
	// add descriptor parser if necessary in furture

	return PMT_ES_BODY_BYTES + m_esInfoLength;
}
