
#ifndef __PESPACKET_H__
#define __PESPACKET_H__


#define PID_INVALID     0x1FFF

class PESPacket
{
public:
    static int SavePacket(PESPacket *pPacket);

public:
    PESPacket();
    PESPacket(unsigned short u16Pid, unsigned char continuityCounter, unsigned char *pu8Data, unsigned short u16Size);
    virtual ~PESPacket();

    bool AppendData(unsigned short u16Pid, unsigned char continuityCounter, unsigned char *pu8Data, unsigned short u16Size);
    bool VerifyCrc32();
    bool IsPESPacketCompleted();
    bool ValidPacket();

    unsigned short Pid(void) { return m_pid; }
    unsigned char* Data(void) { return m_data; }
    unsigned short DataLength(void) { return m_data_length; }
    unsigned short PacketLength(void) { return m_packet_length; }
    unsigned char  StreamId(void) { return m_stream_id; }

private:
    unsigned short m_offset;
    unsigned short m_pid;
    unsigned char *m_data;
    unsigned char  m_continuity_counter;
    unsigned int   m_packet_start_code_prefix; // 24bits: 0x000001
    unsigned char  m_stream_id; // 1 byte
    unsigned short m_packet_length;
    unsigned short m_data_length;
};

#endif
