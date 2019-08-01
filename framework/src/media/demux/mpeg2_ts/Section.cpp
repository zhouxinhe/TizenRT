
//#include <iostream>
//#include <iomanip>

#include <stdio.h>
#include <string.h>
#include "Section.h"
#include "../../utils/MediaUtils.h"

using namespace std;

Section::Section()
	: m_section_length(0)
	, m_offset(0)
	, m_pid(PID_INVALID)
	, m_data(NULL)
	, m_continuity_counter(0xFF)
{
}

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

std::shared_ptr<Section> Section::create(uint16_t u16Pid, uint8_t continuityCounter, uint8_t *pu8Data, uint16_t u16Size)
{
	auto instance = std::make_shared<Section>();
	if (instance && instance->init(u16Pid, continuityCounter, pu8Data, u16Size)) {
		return instance;
	} else {
		printf("%s[line : %d] Fail : init is failed\n", __func__, __LINE__);
		return nullptr;
	}
}

bool Section::init(uint16_t u16Pid, uint8_t continuityCounter, uint8_t *pu8Data, uint16_t u16Size)
{
	if (!pu8Data || u16Size < 3) {
		return false;
	}

	if (pu8Data[0] != 0x47) {
		return false;
	}

	m_section_length = ((uint16_t)(pu8Data[1] & 0x0F) << 8) + (uint16_t)pu8Data[2] + 3;
	m_data = new uint8_t[m_section_length];
	if (!m_data) {
		return false;
	}

	if (u16Size > m_section_length) {
		u16Size = m_section_length;
	}
	memcpy(m_data, pu8Data, u16Size);
	m_offset = u16Size;

	m_pid = u16Pid;
    m_continuity_counter = continuityCounter;
	return true;
}

bool Section::AppendData(uint16_t u16Pid, uint8_t continuityCounter, uint8_t *pu8Data, uint16_t u16Size)
{
    if (m_pid != u16Pid)
    {   // pid not match
        return false;
    }

    if (continuityCounter != ((m_continuity_counter + 1) % 16))
    {   // continuity counter not match
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
	printf("Section::VerifyCrc32 failed\n");
    return false;
}

bool Section::IsSectionCompleted(void)
{
    if (m_section_length == m_offset) {
        return true;
    }

    return false;
}

uint8_t* Section::Data(void)
{
	return m_data;
}

uint16_t Section::Length(void)
{
	return m_section_length;
}

