#ifndef __PES_PACKET_H__
#define __PES_PACKET_H__

#include "Mpeg2TsTypes.h"

class PESPacket
{
public:
    PESPacket();
    PESPacket(uint16_t u16Pid, uint8_t continuityCounter, uint8_t *pu8Data, uint16_t u16Size);
    virtual ~PESPacket();

    bool AppendData(uint16_t u16Pid, uint8_t continuityCounter, uint8_t *pu8Data, uint16_t u16Size);
    bool VerifyCrc32();
    bool IsPESPacketCompleted();
    bool ValidPacket();
    // getters
    uint16_t Pid(void) { return m_pid; }
    uint8_t *Data(void) { return m_data; }
    uint16_t DataLength(void) { return m_data_length; }
    uint16_t PacketLength(void) { return m_packet_length; }
    uint8_t  StreamId(void) { return m_stream_id; }

private:
    uint16_t m_pid;
    uint8_t  m_continuity_counter;
    uint8_t *m_data;
    uint16_t m_data_length;
    uint16_t m_offset;

    uint32_t m_packet_start_code_prefix;
    uint8_t  m_stream_id;
    uint16_t m_packet_length;
};

#endif /* __PES_PACKET_H__ */
