
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "PESPacket.h"
#include "../../utils/MediaUtils.h"

using namespace std;

PESPacket::PESPacket()
	: m_packet_length(0)
	, m_offset(0)
	, m_pid(PID_INVALID)
	, m_data(NULL)
	, m_continuity_counter(0xFF)
{
}

PESPacket::PESPacket(unsigned short u16Pid, unsigned char continuityCounter, unsigned char *pu8Data, unsigned short u16Size)
    : m_packet_start_code_prefix(0)
    , m_stream_id(0)
    , m_data(NULL)
    , m_packet_length(0)
    , m_data_length(0)
    , m_offset(0)
    , m_pid(u16Pid)
    , m_continuity_counter(continuityCounter)
{
	assert(u16Size >= 6);
	m_packet_start_code_prefix = (pu8Data[0] << 16) | (pu8Data[1] << 8) | pu8Data[2];
	m_stream_id = pu8Data[3];
	m_packet_length = (pu8Data[4] << 8) | pu8Data[5];
	m_data_length = 6 + m_packet_length;
    m_data = new unsigned char[m_data_length];

    if (m_data_length <= u16Size) {
        memcpy(m_data, pu8Data, m_data_length);
        m_offset = m_data_length;
    } else {
        memcpy(m_data, pu8Data, u16Size);
        m_offset = u16Size;
    }

	//printf("PES Head: start_code 0x%06X stream_id 0x%02x 6+packet_length 0x%x/0x%x\n", m_packet_start_code_prefix, m_stream_id, m_offset, m_data_length);
}

PESPacket::~PESPacket()
{
    if (m_data != NULL)
    {
        delete[] m_data;
        m_data = NULL;
    }
}

bool PESPacket::AppendData(unsigned short u16Pid, unsigned char continuityCounter, unsigned char *pu8Data, unsigned short u16Size)
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

    if (m_data_length - m_offset >= u16Size)
    {
        memcpy(m_data + m_offset, pu8Data, u16Size);
        m_offset += u16Size;
    }
    else
    {
        memcpy(m_data + m_offset, pu8Data, m_data_length - m_offset);
        m_offset = m_data_length;
    }

	//printf("PES Body: 6+packet_length %#x/%#x\n", m_offset, m_data_length);
    return true;
}

bool PESPacket::VerifyCrc32()
{
    if (media::utils::CRC32_MPEG2(m_data, m_offset) == 0)
    {
        return true;
    }

	printf("PESPacket::VerifyCrc32 failed\n");
    return false;
}

bool PESPacket::ValidPacket()
{
    return (m_packet_start_code_prefix == 0x000001);
}

bool PESPacket::IsPESPacketCompleted()
{
	return (m_data_length == m_offset);
}

