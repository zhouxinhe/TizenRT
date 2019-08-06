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


#ifndef __PARSE_MANAGER_H__
#define __PARSE_MANAGER_H__

#include <map>
#include <vector>

#include "Mpeg2TsTypes.h"

class Section;
class SectionParser;
class ParserManager
{
public:
    ParserManager();
	virtual ~ParserManager();

	bool processSection(ts_pid_t pid, Section *pSection);
	bool IsPatReceived(void);
	bool IsPmtReceived(prog_num_t progNum);
	bool IsPmtReceived(void);
	bool GetAudioStreamInfo(prog_num_t progNum, uint8_t &streamType, ts_pid_t &pid);
    bool GetPrograms(std::vector<prog_num_t> &programs);
    bool GetPmtPidInfo(void);
    bool IsPmtPid(ts_pid_t pid);

protected:
	bool t_AddParser(SectionParser *pParser);
	bool t_RemoveParser(table_id_t tableId);
	SectionParser *t_Parser(table_id_t tableId);
	bool t_Parse(ts_pid_t pid, Section *pSection);

private:
	std::map<table_id_t, SectionParser *> t_tableParserMap;
	std::vector<ts_pid_t> m_PmtPids;
};

#endif
