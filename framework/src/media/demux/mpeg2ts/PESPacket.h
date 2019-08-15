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

#ifndef __PES_PACKET_H
#define __PES_PACKET_H

#include <memory>
#include "Mpeg2TsTypes.h"
#include "Section.h"

class PESPacket : public Section
{
public:
	// should always use this static method to create a new PESPacket instance
	static std::shared_ptr<PESPacket> create(ts_pid_t pid, uint8_t continuityCounter, uint8_t *pData, uint16_t size);
	// constructor and destructor
	PESPacket() {}
	virtual ~PESPacket() {}

protected:
	// parse length field from the given data
	// return length value of the PES packet.
	virtual uint16_t parseLengthField(uint8_t *pData, uint16_t size) override;

#if 0
	// initialize packet member and allocate data buffer
	bool initialize(ts_pid_t pid, uint8_t continuityCounter, uint8_t *pData, uint16_t size);
	// append PES data from TS packet payload
	bool appendData(ts_pid_t pid, uint8_t continuityCounter, uint8_t *pData, uint16_t size);
	// MPEG2 CRC verification
	bool verifyCrc32(void);
	// check if it's a complete PES packet
	bool isCompleted(void);
	// getters
	ts_pid_t getPid(void) { return mPid; }
	uint8_t *getDataPtr(void) { return mPacketData; }
	uint16_t getDataLen(void) { return mPacketDataLen; }

private:
	ts_pid_t mPid;
	uint8_t  mContinuityCounter;
	uint8_t *mPacketData;
	uint16_t mPacketDataLen;
	uint16_t mPresentDataLen;
#endif
};

#endif /* __PES_PACKET_H */
