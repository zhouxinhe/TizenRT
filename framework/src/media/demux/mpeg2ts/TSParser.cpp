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
#include <debug.h>
#include <assert.h>

#include "Section.h"
#include "PATParser.h"
#include "ParseManager.h"
#include "PMTElementary.h"
#include "TSParser.h"
#include "PESPacket.h"
#include "PESParser.h"
#include "Mpeg2TsTypes.h"

#include "../../StreamBuffer.h"
#include "../../StreamBufferReader.h"
#include "../../StreamBufferWriter.h"


using namespace std;

namespace media {
namespace stream {

TSHeader::TSHeader()
	: m_sync_byte(SYNCCODE)
	, m_transport_error_indicator(0)
	, m_payload_unit_start_indicator(0)
	, m_transport_priority(0)
	, m_pid(INVALID_PID)
	, m_transport_scrambling_control(0)
	, m_adaptation_field_control(0)
	, m_continuity_counter(0)
{
}

bool TSHeader::Parse(uint8_t *pbPacketHeader)
{
	m_sync_byte = pbPacketHeader[0];
	if (m_sync_byte != SYNCCODE) {
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

bool AdaptationField::Parse(uint8_t *pAdaptationField)
{
	adaptation_field_length = pAdaptationField[0];
	if (adaptation_field_length > 0) {
		discontinuity_indicator              = (pAdaptationField[1] >> 7) & 0x01;
		random_access_indicator              = (pAdaptationField[1] >> 6) & 0x01;
		elementary_stream_priority_indicator = (pAdaptationField[1] >> 5) & 0x01;
		pcr_flag                             = (pAdaptationField[1] >> 4) & 0x01;
		opcr_flag                            = (pAdaptationField[1] >> 3) & 0x01;
		splicing_point_flag                  = (pAdaptationField[1] >> 2) & 0x01;
		transport_private_data_flag          = (pAdaptationField[1] >> 1) & 0x01;
		adaptation_field_extension_flag      = (pAdaptationField[1]) & 0x01;
	}

	return true;
}

TSParser::TSParser()
	: m_data(nullptr)
	, mReaderOffset(0)
	, mPESPid(-1)
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
		meddbg("TSParser instance init failed!\n");
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
		meddbg("streamBuffer is nullptr!\n");
		return false;
	}

	mStreamBuffer = streamBuffer;
	mBufferReader = std::make_shared<StreamBufferReader>(mStreamBuffer);
	mBufferWriter = std::make_shared<StreamBufferWriter>(mStreamBuffer);
	mReaderOffset = 0;

	if (!mBufferReader || !mBufferWriter) {
		meddbg("mBufferReader/Writer is nullptr!\n");
		return false;
	}

	mParserManager = std::make_shared<ParserManager>();
	if (!mParserManager) {
		meddbg("mParserManager is nullptr!\n");
		return false;
	}

	mPESParser = std::make_shared<PESParser>();
	if (!mPESParser) {
		meddbg("mPESParser is nullptr!\n");
		return false;
	}

	m_data = new uint8_t[TS_PACKET_SIZE];
	if (m_data == nullptr) {
		meddbg("TS packet buffer allocate failed!\n");
		return false;
	}

	return true;
}

std::shared_ptr<ParserManager> TSParser::getParserManager(void)
{
	return mParserManager;
}

size_t TSParser::sizeOfSpace(void)
{
	return mBufferWriter->sizeOfSpace();
}

size_t TSParser::pushData(uint8_t *buf, size_t size)
{
	size_t written = 0;
	if (mBufferWriter) {
		written += mBufferWriter->write(buf, size);
		assert(written == size);
	}
	return written;
}

size_t TSParser::pullData(uint8_t *buf, size_t size, prog_num_t progNum)
{
	if (mPESPid == -1) {
		// setup PES pid
		if (progNum == 0) {
			// use default 1st program
			std::vector<prog_num_t> programs;
			mParserManager->GetPrograms(programs);
			progNum = programs[0];
		}
		uint8_t streamType;
		if (!mParserManager->GetAudioStreamInfo(progNum, streamType, mPESPid)) {
			meddbg("get audio pes pid failed\n");
			return 0;
		}

		medvdbg("setup audio pes pid: 0x%x\n", mPESPid);
	}

	size_t fill = 0;
	size_t need;
	while (fill < size) {
		need = size - fill;
		if (mPESPacket) {
			// get remaining payload in last PES packet
			if (need > mPESParser->ESDataLength() - mPESDataUsed) {
				need = mPESParser->ESDataLength() - mPESDataUsed;
			}

			memcpy(&buf[fill], mPESParser->ESData() + mPESDataUsed, need);
			mPESDataUsed += need;
			fill += need;

			if (mPESDataUsed == mPESParser->ESDataLength()) {
				// read whole es data in one pes packet
				delete mPESPacket;
				mPESPacket = NULL;
				mPESDataUsed = 0;
			}
			continue;
		}

		// get new PES packet
		if (getPESPacket(&mPESPacket) <= 0) {
			// 0 / -1
			break;
		}

		// parse PES packet
		if (mPESParser->Parse(mPESPacket->Data(), mPESPacket->DataLength())) {
			mPESDataUsed = 0;
		} else {
			meddbg("PES parse failed\n");
			assert(0);
		}
	}

	return fill;
}

bool TSParser::getPrograms(std::vector<prog_num_t> &progs)
{
	return mParserManager->GetPrograms(progs);
}

audio_type_t TSParser::getAudioType(prog_num_t progNum)
{
	uint8_t streamType;
	ts_pid_t streamPid;
	if (mParserManager->GetAudioStreamInfo(progNum, streamType, streamPid)) {
		switch (streamType) {
		case PMTElementary::STREAM_TYPE_AUDIO_AAC:
		case PMTElementary::STREAM_TYPE_AUDIO_HE_AAC:
			return AUDIO_TYPE_AAC;
		case PMTElementary::STREAM_TYPE_AUDIO_MPEG1:
			return AUDIO_TYPE_MP3;
		default:
			meddbg("unsupported audio type 0x%x\n", streamType);
			break;
		}
	} else {
		meddbg("didn't get any audio stream info\n");
	}

	return AUDIO_TYPE_INVALID;
}

int TSParser::Adjust(uint8_t *pPacketData, size_t readOffset)
{
	uint8_t buffer[TS_PACKET_SIZE];
	TSHeader tsHeader;
	size_t szRead;
	int syncOffset;
	int count;

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
	uint8_t *pu8Payload = &m_data[4];
	uint8_t  lenPayload = 188 - 4;

	assert(ppSection != nullptr);

	do {
		if (tsHeader.TransportErrorIndicator() != 0) {
			// error
			break;
		}

		if (tsHeader.AdaptationFieldControl() == 0) {
			// reserved
			break;
		}

		if (tsHeader.AdaptationFieldControl() == 2) {
			// no playload, 183 bytes adaption field only
			adaptation_field.Parse(&m_data[4]);
			break;
		}

		if (tsHeader.AdaptationFieldControl() == 3) {
			// 0~182 bytes adaption field + playload
			adaptation_field.Parse(&m_data[4]);
			lenPayload = 188 - 4 - (1 + adaptation_field.FieldLenght());
			pu8Payload = &m_data[188 - lenPayload];
		}

		if (tsHeader.PayloadUnitStartIndicator() == 1) {
			/* new section */
			uint8_t u8PointerField = pu8Payload[0]; // first byte in payload is the pointer field in case of unit start indicator is 1
			if (u8PointerField != 0) {
				/* prev section tail + next section head in this packet */
				it = m_pid_section.find(tsHeader.Pid());
				if (it != m_pid_section.end()) {
					pSection = it->second;
					pSection->AppendData(tsHeader.Pid(), tsHeader.ContinuityCounter(), pu8Payload + 1, u8PointerField);
					if (pSection->IsSectionCompleted()) {
						*ppSection = pSection;
						// no return
					} else {
						// section should finished, abnormal case
						delete it->second;
					}
					// anyway, erase from map
					it->second = NULL;
					m_pid_section.erase(it);
				}
			}

			// new section start
			pSection = new Section(tsHeader.Pid(), tsHeader.ContinuityCounter(), pu8Payload + 1 + u8PointerField, lenPayload - 1 - u8PointerField);
			if (pSection->IsSectionCompleted()) {
				*ppSection = pSection;
				return true;
			} else { // insert to map
				m_pid_section.insert(pair<int, Section *>(tsHeader.Pid(), pSection));
			}
		} else {
			it = m_pid_section.find(tsHeader.Pid());
			if (it != m_pid_section.end()) {
				pSection = it->second;
				pSection->AppendData(tsHeader.Pid(), tsHeader.ContinuityCounter(), pu8Payload, lenPayload); // no point filed
				if (pSection->IsSectionCompleted()) {
					*ppSection = pSection;
					it->second = NULL;
					m_pid_section.erase(it);
					return true;
				}
			}
		}
	} while (0);

	return false;
}

bool TSParser::PESUnpack(TSHeader &tsHeader, PESPacket **ppPESPacket)
{
	PESPacket *pPESPacket = NULL;
	std::map<int, PESPacket *>::iterator it;

	AdaptationField adaptation_field;
	uint8_t *pu8Payload = &m_data[4];
	uint8_t  lenPayload = 188 - 4;

	assert(ppPESPacket != nullptr);

	do {
		if (tsHeader.TransportErrorIndicator() != 0) {
			// error
			break;
		}

		if (tsHeader.AdaptationFieldControl() == 0) {
			// reserved
			break;
		}

		if (tsHeader.AdaptationFieldControl() == 2) {
			// no playload, 183 bytes adaption field only
			adaptation_field.Parse(&m_data[4]);
			break;
		}

		if (tsHeader.AdaptationFieldControl() == 3) {
			// 0~182 bytes adaption field + playload
			adaptation_field.Parse(&m_data[4]);
			lenPayload = 188 - 4 - (1 + adaptation_field.FieldLenght());
			pu8Payload = &m_data[188 - lenPayload];
		}

		if (tsHeader.PayloadUnitStartIndicator() == 1) {
			/* new pes packet start */
			pPESPacket = new PESPacket(tsHeader.Pid(), tsHeader.ContinuityCounter(), pu8Payload, lenPayload);
			if (pPESPacket->IsPESPacketCompleted()) {
				*ppPESPacket = pPESPacket;
				return true;
			} else {
				it = m_pid_pespacket.find(tsHeader.Pid());
				if (it != m_pid_pespacket.end()) {
					// PES packet exist, delete firstly!
					delete it->second;
					it->second = NULL;
					m_pid_pespacket.erase(it);
				}

				m_pid_pespacket.insert(pair<int, PESPacket *>(tsHeader.Pid(), pPESPacket));
			}
		} else {
			it = m_pid_pespacket.find(tsHeader.Pid());
			if (it == m_pid_pespacket.end()) {
				// nothing, PES packet not exit, drop this ts packet!
			} else {
				pPESPacket = it->second;
				pPESPacket->AppendData(tsHeader.Pid(), tsHeader.ContinuityCounter(), pu8Payload, lenPayload);
				if (pPESPacket->IsPESPacketCompleted()) {
					// send pes packet
					*ppPESPacket = pPESPacket;

					it->second = NULL;
					m_pid_pespacket.erase(it);
					return true;
				}
			}
		}
	} while (0);

	return false;
}

void TSParser::ResetPidSection(void)
{
	auto it = m_pid_section.begin();

	while (it != m_pid_section.end()) {
		if (it->second != NULL) {
			delete it->second;
		}
		m_pid_section.erase(it);
		it++;
	}
}

bool TSParser::IsPsiPid(uint16_t pid)
{
	switch (pid) {
	case PATParser::PAT_PID:
		return true;
	default:
		return mParserManager->IsPmtPid(pid);
	}
}

bool TSParser::IsPESPid(uint16_t pid)
{
	return (pid == mPESPid);
}

// return value
// 0: run out of ts packets in buffer
// TS_PACKET_SIZE: got a ts packet
// -1: negative value means failure, maybe not a transport stream
ssize_t TSParser::loadPacket(uint8_t *buf, size_t size, bool sync)
{
	TSHeader tsHeader;
	int syncOffset = 0;

	// load one ts packet data from stream buffer
	assert(size >= TS_PACKET_SIZE);
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

	while ((ret = loadPacket(m_data, TS_PACKET_SIZE, false)) && (ret == TS_PACKET_SIZE)) {
		tsHeader.Parse(m_data);
		if (IsPESPid(tsHeader.Pid())) {
			// PES packets
			if (PESUnpack(tsHeader, ppPESPacket)) {
				// get new PES packet
				return ret;
			}
		}
	}

	return ret;
}

bool TSParser::IsReady(void)
{
	return (mPatRecvFlag && mPmtRecvFlag);
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

	// Load 1st ts packet with force resync
	ret = loadPacket(m_data, TS_PACKET_SIZE, true);
	while (ret == TS_PACKET_SIZE) {
		tsHeader.Parse(m_data);
		if (IsPsiPid(tsHeader.Pid())) {
			// PAT/PMT packets
			Section *pSection = nullptr;
			PSIUnpack(tsHeader, &pSection);
			mParserManager->processSection(tsHeader.Pid(), pSection);
			delete pSection;

			if (!mPatRecvFlag) {
				mPatRecvFlag = mParserManager->IsPatReceived();
				if (mPatRecvFlag) {
					// PAT received
					//mParserManager->GetPmtPidInfo();
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

bool TSParser::IsMpeg2Ts(const uint8_t *buffer, size_t size)
{
	if (!buffer || size < TS_PACKET_SIZE) {
		meddbg("invalid params\n");
		return false;
	}

	int count;
	size_t syncOffset;
	for (syncOffset = 0; syncOffset < TS_PACKET_SIZE; syncOffset++) {
		if (buffer[syncOffset] != SYNCCODE) {
			continue;
		}

		if (size < syncOffset + SYNC_COUNT * TS_PACKET_SIZE) {
			meddbg("data in buffer is not enough for sync verification\n");
			return false;
		}

		for (count = 1; count < SYNC_COUNT; count++) {
			if (buffer[syncOffset + count * TS_PACKET_SIZE] != SYNCCODE) {
				// sync not match
				break;
			}
		}

		if (count == SYNC_COUNT) {
			// sync verification succeed
			return true;
		}
	}

	return false;
}

} // namespace stream
} // namespace media
