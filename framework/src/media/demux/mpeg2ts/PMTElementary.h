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

#ifndef __PMT_ELEMENTARY_H__
#define __PMT_ELEMENTARY_H__

#include "Mpeg2TsTypes.h"

class PMTElementary
{
public:
	enum {
		STREAM_TYPE_AUDIO_MPEG1  = 0x03,
		STREAM_TYPE_AUDIO_MPEG2  = 0x04,
		STREAM_TYPE_AUDIO_AAC    = 0x0F,
		STREAM_TYPE_AUDIO_HE_AAC = 0x11,
		STREAM_TYPE_AUDIO_AC3    = 0x81,
	};

	PMTElementary();
	~PMTElementary();

	uint8_t StreamType(void);
	ts_pid_t ElementaryPID(void);
	int16_t ESInfoLength(void);
	int32_t Parse(uint8_t *pData);

private:
	// stream type
	uint8_t m_streamType;
	// elementary PID
	ts_pid_t m_elementary_PID;
	// ES info length
	int16_t m_esInfoLength;
};

#endif /* __PMT_ELEMENTARY_H__ */
