
#ifndef _TSTREAM_PARSER_H_
#define _TSTREAM_PARSER_H_

#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <list>
#include <memory>

#include <media/MediaTypes.h>


//#include "Section.h"
//#include "SectionParser.h"
//#include "ParseManager.h"
//#include "PESPacket.h"
//#include "PESParser.h"
#include "DTVmwType.h"

#define TS_PACKET_SIZE          188
#define SYNC_COUNT              3
#define SYNCCODE                0x47
#define PES_PACKET_CODE_PREFIX  0x000001
#define TS_PACKET_HEAD_LEN      4

class CParserManager;
class Section;
class PESParser;
class PESPacket;

namespace media {
namespace stream {

class StreamBuffer;
class StreamBufferReader;
class StreamBufferWriter;

class TSHeader
{
public:
    TSHeader();
    virtual ~TSHeader() {}

    bool Parse(unsigned char *pTsBuf);
    unsigned short Pid() {return m_pid;}
    unsigned char TransportErrorIndicator() {return m_transport_error_indicator;}
    unsigned char ContinuityCounter() {return m_continuity_counter;}
    unsigned char AdaptationFieldControl() {return m_adaptation_field_control;}
    bool PayloadUnitStartIndicator() {return static_cast<bool>(m_payload_unit_start_indicator);}

private:
    unsigned char  m_sync_byte;
    unsigned short m_transport_error_indicator    : 1;
    unsigned short m_payload_unit_start_indicator : 1;
    unsigned short m_transport_priority           : 1;
    unsigned short m_pid                          : 13;
    unsigned char  m_transport_scrambling_control : 2;
    unsigned char  m_adaptation_field_control     : 2;
    unsigned char  m_continuity_counter           : 4;
};

class AdaptationField
{
public:
    AdaptationField() : adaptation_field_length(0) {}
    virtual ~AdaptationField() {}
    bool Parse(unsigned char *pAdaptationField);
    unsigned char FieldLenght() { return adaptation_field_length; }

private:
    unsigned char adaptation_field_length;
    unsigned char discontinuity_indicator : 1;
    unsigned char random_access_indicator : 1;
    unsigned char elementary_stream_priority_indicator : 1;
    unsigned char pcr_flag : 1;
    unsigned char opcr_flag : 1;
    unsigned char splicing_point_flag : 1;
    unsigned char transport_private_data_flag : 1;
    unsigned char adaptation_field_extension_flag : 1;
};

class TSParser
{
public:
    TSParser();
    virtual ~TSParser();
    static std::shared_ptr<TSParser> create(void);

    bool init(void);
	// push TS data
	size_t sizeOfSpace(void);
	size_t pushData(unsigned char *buf, size_t size);
	// pull PES data
	size_t pullData(unsigned char *buf, size_t size, TTPN progNum = -1);

    bool getPrograms(std::vector<TTPN> &progs);
	audio_type_t getAudioType(TTPN progNum);

    int PreParse(void);
    //int Parse(void);
    void DumpBuffer(unsigned char *buffer, size_t size, const char *tips = "");

    //bool ReadPESPacket(TSHeader &, unsigned char *, unsigned char **, unsigned short *);
    unsigned int GetTotalTsPacketNum() {return m_total_packet_num;}
    bool IsPsiPid(unsigned short u16Pid);
	bool IsPidNeeded(unsigned short pid);
	bool IsPESPid(unsigned short pid);
	int getPESPacket(PESPacket **ppPESPacket);

private:
	ssize_t readPacket(unsigned char *buf, size_t size);
	ssize_t loadPacket(unsigned char *buf, size_t size, bool sync);

    bool PSIUnpack(TSHeader &tsHeader, Section **ppSection);
	bool PESUnpack(TSHeader &tsHeader, PESPacket **ppPESPacket);
	int Adjust(unsigned char *pPacketData, size_t readOffset);
	void ResetPidSection(void);
	//void StatusReport(int count = 10000);
	std::shared_ptr<CParserManager> getParserManager(void);

private:
    int mStatus; // -1: failed 0: INIT, 1: PAT received, 2:PMT received, 3: PESPid need 4: PES filtering
    bool mPatRecvFlag;
    bool mPmtRecvFlag;
    //PCFile m_tsfile;
    unsigned char *m_data;

	unsigned int            m_total_packet_num;
	std::map<int, Section*> m_pid_section;
	std::map<int, PESPacket*> m_pid_pespacket;

	std::shared_ptr<StreamBuffer> mStreamBuffer;
	std::shared_ptr<StreamBufferReader> mBufferReader;
	std::shared_ptr<StreamBufferWriter> mBufferWriter;
	size_t mReaderOffset;

	std::shared_ptr<CParserManager> mParserManager;
	TTPID mPESPid;
	PESPacket *mPESPacket;
	std::shared_ptr<PESParser> mPESParser;
	size_t mPESDataUsed;

};

} // namespace stream
} // namespace media

#endif

