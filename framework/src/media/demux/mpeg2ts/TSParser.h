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

#ifndef _TS_PARSER_H_
#define _TS_PARSER_H_

#include <stdio.h>
#include <stdint.h>

#include <string>
#include <vector>
#include <map>
#include <list>
#include <memory>

#include <media/MediaTypes.h>


#define TS_PACKET_SIZE          188
#define SYNC_COUNT              3
#define SYNCCODE                0x47
#define PES_PACKET_CODE_PREFIX  0x000001
#define TS_PACKET_HEAD_LEN      4

class ParserManager;
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

	bool Parse(uint8_t *pData);
	uint16_t Pid() { return m_pid; }
	uint8_t TransportErrorIndicator() { return m_transport_error_indicator; }
	uint8_t ContinuityCounter() { return m_continuity_counter;}
	uint8_t AdaptationFieldControl() { return m_adaptation_field_control; }
	bool PayloadUnitStartIndicator() { return static_cast<bool>(m_payload_unit_start_indicator); }

private:
	uint8_t  m_sync_byte;
	uint16_t m_transport_error_indicator : 1;
	uint16_t m_payload_unit_start_indicator : 1;
	uint16_t m_transport_priority : 1;
	uint16_t m_pid : 13;
	uint8_t  m_transport_scrambling_control : 2;
	uint8_t  m_adaptation_field_control : 2;
	uint8_t  m_continuity_counter : 4;
};

class AdaptationField
{
public:
	AdaptationField() : adaptation_field_length(0) {}
	virtual ~AdaptationField() {}
	bool Parse(uint8_t *pAdaptationField);
	uint8_t FieldLenght() { return adaptation_field_length; }

private:
	uint8_t adaptation_field_length;
	uint8_t discontinuity_indicator : 1;
	uint8_t random_access_indicator : 1;
	uint8_t elementary_stream_priority_indicator : 1;
	uint8_t pcr_flag : 1;
	uint8_t opcr_flag : 1;
	uint8_t splicing_point_flag : 1;
	uint8_t transport_private_data_flag : 1;
	uint8_t adaptation_field_extension_flag : 1;
};

class TSParser
{
public:
	TSParser();
	virtual ~TSParser();
	static std::shared_ptr<TSParser> create(void);

	bool init(void);
	// space size available for push
	size_t sizeOfSpace(void);
	// push TS data
	size_t pushData(uint8_t *buf, size_t size);
	// pull PES data
	size_t pullData(uint8_t *buf, size_t size, uint16_t progNum = 0);

	bool getPrograms(std::vector<uint16_t> &progs);
	audio_type_t getAudioType(uint16_t progNum);

	bool IsReady(void);
	int PreParse(void);

	bool IsPsiPid(uint16_t u16Pid);
	bool IsPidNeeded(uint16_t pid);
	bool IsPESPid(uint16_t pid);
	int getPESPacket(PESPacket **ppPESPacket);

	static bool IsMpeg2Ts(const uint8_t *buffer, size_t size);

private:
	ssize_t readPacket(uint8_t *buf, size_t size);
	ssize_t loadPacket(uint8_t *buf, size_t size, bool sync);

	bool PSIUnpack(TSHeader &tsHeader, Section **ppSection);
	bool PESUnpack(TSHeader &tsHeader, PESPacket **ppPESPacket);
	int Adjust(uint8_t *pPacketData, size_t readOffset);
	void ResetPidSection(void);
	std::shared_ptr<ParserManager> getParserManager(void);

private:
	bool mPatRecvFlag;
	bool mPmtRecvFlag;
	uint8_t *m_data;

	std::map<int, Section*> m_pid_section;
	std::map<int, PESPacket*> m_pid_pespacket;

	std::shared_ptr<StreamBuffer> mStreamBuffer;
	std::shared_ptr<StreamBufferReader> mBufferReader;
	std::shared_ptr<StreamBufferWriter> mBufferWriter;
	size_t mReaderOffset;

	std::shared_ptr<ParserManager> mParserManager;
	int16_t mPESPid;
	PESPacket *mPESPacket;
	std::shared_ptr<PESParser> mPESParser;
	size_t mPESDataUsed;
};

} // namespace stream
} // namespace media

#endif
