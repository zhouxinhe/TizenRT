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

#include <debug.h>
#include <string.h>

#include "PESPacket.h"
#include "Mpeg2TsTypes.h"
//#include "../../utils/MediaUtils.h"

#define PACKET_LENGTH(buffer)               ((buffer[4] << 8) | buffer[5])
#define PES_PACKET_HEAD_BYTES               (6) // packet_start_code_prefix + stream_id + PES_packet_length

std::shared_ptr<PESPacket> PESPacket::create(ts_pid_t pid, uint8_t continuityCounter, uint8_t *pData, uint16_t size)
{
	auto instance = std::make_shared<PESPacket>();
	if (instance && instance->initialize(pid, continuityCounter, pData, size)) {
		return instance;
	}

	meddbg("create PESPacket instance failed!\n");
	return nullptr;
}

#if 0
bool PESPacket::initialize(ts_pid_t pid, uint8_t continuityCounter, uint8_t *pData, uint16_t size)
{
	mPacketDataLen = PES_PACKET_HEAD_BYTES + PACKET_LENGTH(pData);
	mPacketData = new uint8_t[mPacketDataLen];
	if (!mPacketData) {
		meddbg("Run out of memory! Allocating %d bytes failed!\n", mPacketDataLen);
		return false;
	}

	if (mPacketDataLen < size) {
		mPresentDataLen = mPacketDataLen;
	} else {
		mPresentDataLen = size;
	}
	memcpy(mPacketData, pData, mPresentDataLen);

	mPid = pid;
	mContinuityCounter = continuityCounter;
	return true;
}

PESPacket::PESPacket()
	: mPid(INVALID_PID)
	, mContinuityCounter(0)
	, mPacketData(nullptr)
	, mPacketDataLen(0)
	, mPresentDataLen(0)
{
}

PESPacket::~PESPacket()
{
	if (mPacketData) {
		delete[] mPacketData;
		mPacketData = nullptr;
	}
}
#endif

uint16_t PESPacket::parseLengthField(uint8_t *pData, uint16_t size)
{
	return (PES_PACKET_HEAD_BYTES + PACKET_LENGTH(pData));
}

#if 0
bool PESPacket::appendData(ts_pid_t pid, uint8_t continuityCounter, uint8_t *pData, uint16_t size)
{
	if (mPid != pid) {
		meddbg("pid(0x%x) do not match, current 0x%x\n", pid, mPid);
		return false;
	}

	if (continuityCounter != ((mContinuityCounter + 1) % CONTINUITY_COUNTER_MOD)) {
		meddbg("continuity counter(0x%x) do not match, current 0x%x\n", continuityCounter, mContinuityCounter);
		return false;
	}

	mContinuityCounter = continuityCounter;

	if (mPacketDataLen - mPresentDataLen >= size) {
		memcpy(mPacketData + mPresentDataLen, pData, size);
		mPresentDataLen += size;
	} else {
		memcpy(mPacketData + mPresentDataLen, pData, mPacketDataLen - mPresentDataLen);
		mPresentDataLen = mPacketDataLen;
	}

	return true;
}

bool PESPacket::verifyCrc32(void)
{
	if (media::utils::CRC32_MPEG2(mPacketData, mPresentDataLen) != 0) {
		meddbg("mpeg2 crc32 verification failed!\n");
		return false;
	}

	return true;
}

bool PESPacket::isCompleted(void)
{
	return (mPacketDataLen == mPresentDataLen);
}
#endif