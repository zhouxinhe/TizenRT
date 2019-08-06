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

#include <stdio.h>
#include <string.h>
#include "Section.h"
#include "Mpeg2TsTypes.h"
#include "../../utils/MediaUtils.h"


Section::Section(uint16_t u16Pid, uint8_t continuityCounter, uint8_t *pu8Data, uint16_t u16Size)
	: m_section_length(0)
	, m_offset(0)
	, m_pid(u16Pid)
	, m_data(NULL)
	, m_continuity_counter(continuityCounter)
{
	m_section_length = ((uint16_t)(pu8Data[1] & 0x0F) << 8) + (uint16_t)pu8Data[2] + 3;
	m_data = new uint8_t[m_section_length];

	if (m_section_length <= u16Size) {
		memcpy(m_data, pu8Data, m_section_length);
		m_offset += m_section_length;
	} else {
		memcpy(m_data, pu8Data, u16Size);
		m_offset += u16Size;
	}
}

Section::~Section()
{
	if (m_data != NULL) {
		delete[] m_data;
		m_data = NULL;
	}
}

bool Section::AppendData(uint16_t u16Pid, uint8_t continuityCounter, uint8_t *pu8Data, uint16_t u16Size)
{
	if (m_pid != u16Pid) {   // pid not match
		return false;
	}

	if (continuityCounter != ((m_continuity_counter + 1) % CONTINUITY_COUNTER_MOD)) {
		// continuity counter not match
		return false;
	}

	m_continuity_counter = continuityCounter;

	if (m_section_length - m_offset >= u16Size) {
		memcpy(m_data + m_offset, pu8Data, u16Size);
		m_offset += u16Size;
	} else {
		memcpy(m_data + m_offset, pu8Data, m_section_length - m_offset);
		m_offset = m_section_length;
	}

	return true;
}

bool Section::VerifyCrc32(void)
{
	if (media::utils::CRC32_MPEG2(m_data, m_offset) == 0) {
		return true;
	}

	return false;
}

bool Section::IsSectionCompleted(void)
{
	if (m_section_length == m_offset) {
		return true;
	}

	return false;
}

uint8_t *Section::Data(void)
{
	return m_data;
}

uint16_t Section::Length(void)
{
	return m_section_length;
}
