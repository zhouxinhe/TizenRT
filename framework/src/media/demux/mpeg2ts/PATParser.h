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

#ifndef __PAT_PARSER_H__
#define __PAT_PARSER_H__

#include <map>
#include "Mpeg2TsTypes.h"
#include "SectionParser.h"
#include "BaseSection.h"


class PATParser : public SectionParser, public BaseSection
{
public:
	enum {
		TABLE_ID = 0x00,
		NETWORK_PID = 0x00,
	};

	PATParser();

	virtual ~PATParser();

	virtual void DeleteAll(void);

	size_t NumOfProgramList(void);

	prog_num_t ProgramNumber(uint32_t index);

	ts_pid_t ProgramPID(prog_num_t programNumber);

	stream_id_t TansportStreamId(void);

	ts_pid_t NetworkPID(void);

	bool IsRecv(void);

protected:
	virtual bool t_Create(void);

	virtual void t_Initialize(void);

	virtual bool t_Parse(uint8_t *pData, uint32_t size);

	void t_AddProgram(prog_num_t programNumber, ts_pid_t programPID);

private:
	std::map<prog_num_t, ts_pid_t> m_programMap;

	stream_id_t m_transportStreamId;

	ts_pid_t m_networkPID;
};

#endif /* __PAT_PARSER_H__ */

