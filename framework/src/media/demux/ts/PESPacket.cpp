
#include <iostream>
#include <iomanip>
#include <stdio.h>

#include "crc.h"
#include "PESPacket.h"

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
: m_packet_start_code_prefix(0),
  m_stream_id(0),
  m_data(NULL),
  m_packet_length(0),
  m_data_length(0),
  m_offset(0),
  m_pid(u16Pid),
  m_continuity_counter(continuityCounter)
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
    if (CRC::CRC_MPEG32(m_data, m_offset) == 0)
    {
        return true;
    }

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

int PESPacket::SavePacket(PESPacket *pPacket)
{
	if (pPacket == NULL)
		return -1;

	// write pes data

	unsigned char *pu8Data = pPacket->Data() + 6;
	unsigned char pts_dts_flag = (pu8Data[1] & 0xc0) >> 6;
	//unsigned char header_data_length = pu8Data[2];
	if (pts_dts_flag & 0x2)
	{	// has PTS
	#if 0
		unsigned long long pts; // TODO: 64bits type
		unsigned long long pts32_30;
		unsigned short pts29_15, pts14_0;
		#define MKWORD(h, l) (((h) << 8) | (l))

		pts32_30 = (pu8Data[i] & 0x0e) >> 1;
		pts29_15 = MKWORD(pu8Data[i+1], pu8Data[i+2] & 0xfe) >> 1;
		pts14_0  = MKWORD(pu8Data[i+3], pu8Data[i+4] & 0xfe) >> 1;
		pts = (pts32_30 << 30) | (pts29_15 << 15) | pts14_0;
		pts = pts / 90000;
	#endif
//		unsigned char buffer[5+4+2]; // pts + offset + len
//		memcpy(buffer, pu8Data + 3, 5); // 5bytes PTS
//
//		buffer[5] = (offset >> 24) & 0xFF;
//		buffer[6] = (offset >> 16) & 0xFF;
//		buffer[7] = (offset >>  8) & 0xFF;
//		buffer[8] = (offset      ) & 0xFF;
//
//		unsigned short len = pPacket->DataLength();
//		buffer[9]  = (len >> 8) & 0xFF;
//		buffer[10] = (len     ) & 0xFF;

		// write index data
	}

	return 0;
}

