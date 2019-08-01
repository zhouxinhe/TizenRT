
#include <iostream>
#include <iomanip>
#include <map>

#include <stdio.h>
#include <string.h>
#include <debug.h>
#include <assert.h>

#include "Section.h"
//#include "SectionParser.h"
#include "ParseManager.h"
#include "TSParser.h"
#include "PESPacket.h"
#include "PESParser.h"
#include "BaseDesc.h"
#include "Descriptor.h"

#include "../../StreamBuffer.h"
#include "../../StreamBufferReader.h"
#include "../../StreamBufferWriter.h"



using namespace std;

namespace media {
namespace stream {

TSHeader::TSHeader()
: m_sync_byte(SYNCCODE),
  m_transport_error_indicator(0),
  m_payload_unit_start_indicator(0),
  m_transport_priority(0),
  m_pid(PID_INVALID),
  m_transport_scrambling_control(0),
  m_adaptation_field_control(0),
  m_continuity_counter(0)
{
}

bool TSHeader::Parse(unsigned char *pbPacketHeader)
{
    m_sync_byte = pbPacketHeader[0];
    if (m_sync_byte != SYNCCODE)
    {
        printf("[TSHeader::Parse] %02x %02x %02x %02x\n", pbPacketHeader[0], pbPacketHeader[1], pbPacketHeader[2], pbPacketHeader[3]);
        return false;
    }

    m_transport_error_indicator    = (pbPacketHeader[1] & 0x80) >> 7;
    m_payload_unit_start_indicator = (pbPacketHeader[1] & 0X40) >> 6;
    m_transport_priority           = (pbPacketHeader[1] & 0x20) >> 5;
    m_pid                          = (pbPacketHeader[1] & 0x1F) << 8;
    m_pid                         |= (pbPacketHeader[2]);
    m_transport_scrambling_control = (pbPacketHeader[3] & 0xC0) >> 6;
    m_adaptation_field_control     = (pbPacketHeader[3] & 0x30) >> 4;
    m_continuity_counter           = (pbPacketHeader[3] & 0x0F);

    return true;
}

bool AdaptationField::Parse(unsigned char *pAdaptationField)
{
	adaptation_field_length = pAdaptationField[0];
	if (adaptation_field_length <= 0)
	{
		printf("AdaptationField:: adaptation_field_length 0\n");
		return true;
	}

	discontinuity_indicator              = (pAdaptationField[1] >> 7) & 0x01;
	random_access_indicator              = (pAdaptationField[1] >> 6) & 0x01;
	elementary_stream_priority_indicator = (pAdaptationField[1] >> 5) & 0x01;
	pcr_flag                             = (pAdaptationField[1] >> 4) & 0x01;
	opcr_flag                            = (pAdaptationField[1] >> 3) & 0x01;
	splicing_point_flag                  = (pAdaptationField[1] >> 2) & 0x01;
	transport_private_data_flag          = (pAdaptationField[1] >> 1) & 0x01;
	adaptation_field_extension_flag      = (pAdaptationField[1]) & 0x01;

	//printf("AdaptationField: field_length %d discontinuity %d random_access %d\n",
	//					      adaptation_field_length, discontinuity_indicator, random_access_indicator);

	return true;
}

TSParser::TSParser()
	: m_data(nullptr)
	, m_total_packet_num(0)
	, mPESPid(-1)
	, mReaderOffset(0)
	, mPESDataUsed(0)
{
	mPatRecvFlag = false;
	mPmtRecvFlag = false;
	mPESPacket = NULL;
	// init other members
}

TSParser::~TSParser()
{
	if (m_data) {
		delete m_data;
		m_data = nullptr;
    }
	// delete pPESPacket
}

std::shared_ptr<TSParser> TSParser::create(void)
{
	auto instance = std::make_shared<TSParser>();
	if (instance && instance->init()) {
		return instance;
	} else {
		printf("[%s] L%d, init failed\n", __func__, __LINE__);
		return nullptr;
	}
}

bool TSParser::init(void)
{
	auto streamBuffer = StreamBuffer::Builder()
							.setBufferSize(4096)
							.setThreshold(2048)
							.build();
	if (!streamBuffer) {
		printf("streamBuffer is nullptr!\n");
		return false;
	}

	mStreamBuffer = streamBuffer;
	mBufferReader = std::make_shared<StreamBufferReader>(mStreamBuffer);
	mBufferWriter = std::make_shared<StreamBufferWriter>(mStreamBuffer);
	mReaderOffset = 0;

	if (!mBufferReader || !mBufferWriter) {
		printf("mBufferReader/Writer is nullptr!\n");
		return false;
	}

	mParserManager = std::make_shared<CParserManager>();
	if (!mParserManager) {
		printf("mParserManager is nullptr!\n");
		return false;
	}

	mPESParser = std::make_shared<PESParser>();
	if (!mPESParser) {
		printf("mPESParser is nullptr!\n");
		return false;
	}

    m_data = new unsigned char[TS_PACKET_SIZE];
    if (m_data == nullptr)
    {
        printf("TS packet buffer allocate failed!\n");
        return false;
    }

    return true;
}

std::shared_ptr<CParserManager> TSParser::getParserManager(void)
{
	return mParserManager;
}

size_t TSParser::sizeOfSpace(void)
{
	return mBufferWriter->sizeOfSpace();
}

size_t TSParser::pushData(unsigned char *buf, size_t size)
{
	size_t written = 0;
	if (mBufferWriter) {
		written += mBufferWriter->write(buf, size);
		assert(written == size);
	}
	return written;
}

size_t TSParser::pullData(unsigned char *buf, size_t size, TTPN progNum)
{
	printf("[%s] progNum %d, size %lu\n", __FUNCTION__, progNum, size);

	if (mPESPid == -1) {
		// setup PES pid
		if (!mParserManager->GetAudioPESPid(progNum, mPESPid)) {
			printf("[%s] get audio pes pid failed\n", __FUNCTION__);
			return 0;
		}

		printf("[%s] setup audio pes pid: 0x%x\n", __FUNCTION__, mPESPid);
	}

	size_t fill = 0;
	size_t need;
	while (fill < size) {
		need = size - fill;
		if (mPESPacket) {
			printf("[%s] already used %lu, packetlen %lu\n", __FUNCTION__, mPESDataUsed, mPESParser->ESDataLength());
			// get remaining payload in last PES packet
			if (need > mPESParser->ESDataLength() - mPESDataUsed) {
				need = mPESParser->ESDataLength() - mPESDataUsed;
			}

			memcpy(&buf[fill], mPESParser->ESData() + mPESDataUsed, need);
			mPESDataUsed += need;
			fill += need;

			if (mPESDataUsed == mPESParser->ESDataLength()) {
				printf("[%s] read whole es data in one pes packet\n", __FUNCTION__);
				delete mPESPacket;
				mPESPacket = NULL;
				mPESDataUsed = 0;
			}

			printf("[%s] read %lu/%lu bytes\n", __FUNCTION__, fill, size);
			continue;
		}

		// get new PES packet
		if (getPESPacket(&mPESPacket) <= 0) {
			// 0 / -1
			break;
		}

		// dump PES packet
		assert(mPESPacket);
		//DumpBuffer(mPESPacket->Data(), mPESPacket->DataLength(), "PES packet");

		// parse PES packet
		if (mPESParser->Parse(mPESPacket->Data(), mPESPacket->DataLength())) {
			//DumpBuffer(mPESParser->ESData(), mPESParser->ESDataLength(), "ES");
			mPESDataUsed = 0;
		} else {
			printf("[%s] PES parse failed\n", __FUNCTION__);
			assert(0);
		}
	}

	return fill;
}

bool TSParser::getPrograms(std::vector<TTPN> &progs)
{
	return mParserManager->GetPrograms(progs);
}

int TSParser::Adjust(unsigned char *pPacketData, size_t readOffset)
{
	unsigned char buffer[TS_PACKET_SIZE];
	TSHeader tsHeader;
	size_t szRead;
	int syncOffset;
	int count;

	printf("Adjust called at offet: 0x %08x\n", readOffset);

    for (syncOffset = 0; syncOffset < TS_PACKET_SIZE; syncOffset++) {
        if (pPacketData[syncOffset] != SYNCCODE) {
			continue;
        }

		// found sync byte, now do sync verification!
		for (count = 1; count < SYNC_COUNT; count++) {
			szRead = mBufferReader->copy(buffer, TS_PACKET_SIZE, readOffset + syncOffset + count * TS_PACKET_SIZE);
			if (szRead != TS_PACKET_SIZE) {
				// data in buffer is not enough for sync verification
				return -1;
			}

            if (!tsHeader.Parse(buffer)) {
				// sync not match
				break;
            }
		}

		if (count == SYNC_COUNT) {
			// sync verification succeed
			return syncOffset;
		}
    }

	// Do not find sync byte in one ts packet (188 bytes),
	// maybe it's not a transport stream.
    return TS_PACKET_SIZE;
}


bool TSParser::PSIUnpack(TSHeader &tsHeader, Section **ppSection)
{
	Section *pSection = NULL;
	std::map<int, Section *>::iterator it;

	AdaptationField adaptation_field;
	unsigned char *pu8Payload = &m_data[4];
	unsigned char  lenPayload = 188 - 4;

	assert(ppSection != nullptr);

	do {
		//printf("\nTS: PayloadUnitStartIndicator %d AdaptationFieldControl %d ContinuityCounter %d\n",
		//	tsHeader.PayloadUnitStartIndicator(), tsHeader.AdaptationFieldControl(), tsHeader.ContinuityCounter());

		if (tsHeader.TransportErrorIndicator() != 0)
		{	// error
			break;
		}

		if (tsHeader.AdaptationFieldControl() == 0)
		{	// reserved
			break;
		}

		if (tsHeader.AdaptationFieldControl() == 2)
		{	// no playload, 183 bytes adaption field only
			adaptation_field.Parse(&m_data[4]);
			break;
		}

		if (tsHeader.AdaptationFieldControl() == 3)
		{	// 0~182 bytes adaption field + playload
			adaptation_field.Parse(&m_data[4]);
			lenPayload = 188 - 4 - (1 + adaptation_field.FieldLenght());
			pu8Payload = &m_data[188 - lenPayload];
			printf("adapataionfieldcontrol is 3, field len: %d, getchar()... press any key!\n", adaptation_field.FieldLenght());
			//getchar();
		}

        if (tsHeader.PayloadUnitStartIndicator() == 1)
        {   /* new section */
            unsigned char u8PointerField = pu8Payload[0]; // first byte in payload is the pointer field in case of unit start indicator is 1
            if (u8PointerField != 0)
            {   /* prev section tail + next section head in this packet */
                it = m_pid_section.find(tsHeader.Pid());
                if (it != m_pid_section.end())
                {
                    pSection = it->second;
                    pSection->AppendData(tsHeader.Pid(), tsHeader.ContinuityCounter(), pu8Payload + 1, u8PointerField); // skip u8PointerField byte
                    if (pSection->IsSectionCompleted())
                    {
                        //event.type = CParserManager::EVENT_SECTION_DATA;
                        //event.receiver = (PCHandler *)(CParserManager::Instance());
                        //event.param.l[0] = (long)tsHeader.Pid();
                        //event.param.l[1] = (long)pSection;
                        //PCTask::Send(&event, sync);
						*ppSection = pSection;
                        // no return
                    }
                    else
                    {   // section should finished, abnormal...
                        delete it->second;
                    }
					// anyway, erase from map
                    it->second = NULL;
                    m_pid_section.erase(it);
                }
            }

			// new section start
            pSection = new Section(tsHeader.Pid(), tsHeader.ContinuityCounter(), pu8Payload + 1 + u8PointerField, lenPayload - 1 - u8PointerField); // skip u8PointerField byte and u8PointerField data
            if (pSection->IsSectionCompleted())
            {
				*ppSection = pSection;
                return true;
            }
            else
            {	// insert to map
                m_pid_section.insert(pair<int, Section *>(tsHeader.Pid(), pSection));
            }
        }
        else
        {
            it = m_pid_section.find(tsHeader.Pid());
            if (it != m_pid_section.end())
            {
                pSection = it->second;
                pSection->AppendData(tsHeader.Pid(), tsHeader.ContinuityCounter(), pu8Payload, lenPayload); // no point filed
                if (pSection->IsSectionCompleted())
                {
					*ppSection = pSection;
                    it->second = NULL;
                    m_pid_section.erase(it);
                    return true;
                }
            }
        }
    } while(0);

    return false;
}

bool TSParser::PESUnpack(TSHeader &tsHeader, PESPacket **ppPESPacket)
{
	PESPacket *pPESPacket = NULL;
	std::map<int, PESPacket *>::iterator it;

	AdaptationField adaptation_field;
	unsigned char *pu8Payload = &m_data[4];
	unsigned char  lenPayload = 188 - 4;

	assert(ppPESPacket != nullptr);

    do
    {
		//printf("\nTS: PayloadUnitStartIndicator %d AdaptationFieldControl %d ContinuityCounter %d\n",
		//	tsHeader.PayloadUnitStartIndicator(), tsHeader.AdaptationFieldControl(), tsHeader.ContinuityCounter());

		if (tsHeader.TransportErrorIndicator() != 0)
		{	// error
			break;
		}

		if (tsHeader.AdaptationFieldControl() == 0)
		{	// reserved
			break;
		}

//		if (IsTTXPid(tsHeader.Pid()) && tsHeader.AdaptationFieldControl() != 1)
//		{	// EBU Teletext, adaptation field control flag is always 1.
//			break;
//		}

		if (tsHeader.AdaptationFieldControl() == 2)
		{	// no playload, 183 bytes adaption field only
			adaptation_field.Parse(&m_data[4]);
			break;
		}

		if (tsHeader.AdaptationFieldControl() == 3)
		{	// 0~182 bytes adaption field + playload
			adaptation_field.Parse(&m_data[4]);
			lenPayload = 188 - 4 - (1 + adaptation_field.FieldLenght());
			pu8Payload = &m_data[188 - lenPayload];
		}

		if (tsHeader.PayloadUnitStartIndicator() == 1)
		{	/* new pes packet start */
			pPESPacket = new PESPacket(tsHeader.Pid(), tsHeader.ContinuityCounter(), pu8Payload, lenPayload);
			if (pPESPacket->IsPESPacketCompleted())
			{
				// send pes packet
				//event.type = PCTask::EVENT_USER;
				//event.receiver = (PCHandler *)(CParserManager::Instance());
				//event.param.l[0] = (long)tsHeader.Pid();
				//event.param.l[1] = (long)pPESPacket;
				//PCTask::Send(&event, sync);
				*ppPESPacket = pPESPacket;
				return true;
			}
			else
			{
				it = m_pid_pespacket.find(tsHeader.Pid());
				if (it != m_pid_pespacket.end())
				{
					printf("PES packet exist, delete firstly!\n");
					delete it->second;
					it->second = NULL;
					m_pid_pespacket.erase(it);
				}

				m_pid_pespacket.insert(pair<int, PESPacket *>(tsHeader.Pid(), pPESPacket));
			}
		}
		else
		{
			it = m_pid_pespacket.find(tsHeader.Pid());
			if (it == m_pid_pespacket.end())
			{
				// nothing
				printf("PES packet not exit, drop this ts packet!\n");
			}
			else
			{
				pPESPacket = it->second;
				pPESPacket->AppendData(tsHeader.Pid(), tsHeader.ContinuityCounter(), pu8Payload, lenPayload);
				if (pPESPacket->IsPESPacketCompleted())
				{
					// send pes packet
					*ppPESPacket = pPESPacket;

					it->second = NULL;
					m_pid_pespacket.erase(it);
					return true;
				}
			}
		}
    } while(0);

    return false;
}

void TSParser::ResetPidSection(void)
{
    map<int, Section *>::iterator it;

    for (it = m_pid_section.begin(); it != m_pid_section.end(); /*NULL*/)
    {
        if (it->second != NULL)
            delete it->second;
        m_pid_section.erase(it++);
    }
}

bool TSParser::IsPsiPid(unsigned short pid)
{
	//printf("[%s] pid 0x%x\n", __FUNCTION__, pid);
    switch (pid) {
        case TCPATParser::PAT_PID:
			return true;

        default:
            return mParserManager->IsPmtPid(pid);
    }
}

bool TSParser::IsPESPid(unsigned short pid)
{
	//printf("[%s] pid 0x%x = %x \n", __FUNCTION__, pid, mPESPid);
	return (pid == mPESPid);
}

// return value
// 0: run out of ts packets in buffer
// TS_PACKET_SIZE: got a ts packet
// -1: negative value means failure, maybe not a transport stream
ssize_t TSParser::loadPacket(unsigned char *buf, size_t size, bool sync)
{
	TSHeader tsHeader;
	int syncOffset = 0;

	// load one ts packet data from stream buffer
	assert(size == TS_PACKET_SIZE);
	size = mBufferReader->copy(buf, TS_PACKET_SIZE, mReaderOffset);
	if (size != TS_PACKET_SIZE) {
		// data in buffer is not enough
		return 0;
	}

	// if force sync or packet invalid, then need resync...
    if (sync || !tsHeader.Parse(buf)) {
		syncOffset = Adjust(buf, mReaderOffset);
        if (syncOffset < 0) {
			// data in buffer is not enough to find a valid packet
            return 0; // TODO: add error code
        }

		if (syncOffset >= TS_PACKET_SIZE) {
			// sync failed
			return -1;
		}

		if (syncOffset != 0) {
			size = mBufferReader->copy(buf, TS_PACKET_SIZE, mReaderOffset + (size_t)syncOffset);
			assert(size == TS_PACKET_SIZE);
			mReaderOffset += syncOffset;
		}

		//tsHeader.Parse(buf); // need reparse header if tsHeader is class member
	}

	//DumpBuffer(buf, size, "TS Packet");

	// valid ts packet loaded
	mReaderOffset += TS_PACKET_SIZE;
	mBufferReader->read(NULL, mReaderOffset, false);
	mReaderOffset = 0;

	return TS_PACKET_SIZE;
}


// return value
// 0: run out of ts packets in buffer
// TS_PACKET_SIZE: got a PES packet
// -1: negative value means failure, maybe not a transport stream
int TSParser::getPESPacket(PESPacket **ppPESPacket)
{
	ssize_t ret;
	TSHeader tsHeader;

	//printf("[%s] \n", __FUNCTION__);

	while ((ret = loadPacket(m_data, TS_PACKET_SIZE, false)) && (ret == TS_PACKET_SIZE)) {
		tsHeader.Parse(m_data);
		if (IsPESPid(tsHeader.Pid())) {
			// PES packets
			if (PESUnpack(tsHeader, ppPESPacket)) {
				// get new PES packet
				printf("[%s] succeed\n", __FUNCTION__);
				return ret;
			}
		}
	}

	//printf("[%s] failed, ret %lu\n", __FUNCTION__, ret);
	return ret;
}

// preparse ts stream buffer, get PAT and PMT info.
// return value
// 0: run out of ts packets in buffer
// 1: pre-parse succeed
// -1: negative value means failure, maybe not a transport stream

int TSParser::PreParse(void)
{
	TSHeader tsHeader;
	ssize_t ret;

	printf("[%s] \n", __FUNCTION__);

	// Load 1st ts packet with force resync
	ret = loadPacket(m_data, TS_PACKET_SIZE, true);
	while (ret == TS_PACKET_SIZE) {
		tsHeader.Parse(m_data);
		if (IsPsiPid(tsHeader.Pid())) {
			// PAT/PMT packets
			Section *pSection = nullptr;
			PSIUnpack(tsHeader, &pSection);
			mParserManager->processSection(tsHeader.Pid(), pSection);
			if (!mPatRecvFlag) {
				mPatRecvFlag = mParserManager->IsPatReceived();
				if (mPatRecvFlag) {
					// PAT received
					mParserManager->GetPmtPidInfo();
				}
			} else if (!mPmtRecvFlag) {
				mPmtRecvFlag = mParserManager->IsPmtReceived();
				if (mPmtRecvFlag) {
					// All PMTs received
					return 1;
				}
			} else {
				// PAT + PMTs already received
				// do not need to pre-parse again...
				return 1;
			}
		}

		ret = loadPacket(m_data, TS_PACKET_SIZE, false);
	}

	return ret;
}

void TSParser::DumpBuffer(unsigned char *buffer, size_t size, const char *tips)
{
	size_t i;
	printf("\n### %s data %p size 0x%x(%lu) ###", tips, buffer, size, size);
	for (i = 0; i < size; i++) {
		if (i % 16 == 0) {
			printf("\n");
		}
		printf("%02x ", buffer[i]);
	}
	printf("\n\n");
}

} // namespace stream
} // namespace media

