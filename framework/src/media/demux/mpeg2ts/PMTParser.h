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

#ifndef __PMT_PARSER_H__
#define __PMT_PARSER_H__

#include <map>
#include "Mpeg2TsTypes.h"
#include "SectionParser.h"

class Section;
class PMTInstance;
class PMTParser : public SectionParser
{
public:
	enum {
		TABLE_ID = 0x02,
	};

	PMTParser();
	virtual ~PMTParser();

	size_t NumOfPMTInstance(void);

	prog_num_t ProgramNumber(void);

	PMTInstance *GetPMTInstance(prog_num_t programNumber);

	PMTInstance *PMTInstanceOfIndex(uint32_t index);

	void UpdatePMTElements(std::map<int, ts_pid_t> &pmtMap);

	void ClearPMTElements(void);

	static int makeKey(ts_pid_t pid, prog_num_t progNum);

protected:
	virtual void t_Initialize(void);

	virtual bool t_Parse(uint8_t *pData, uint32_t size);

private:
	prog_num_t m_programNumber;

	std::map<int, ts_pid_t> m_PMTElements;  // <key = (pid<<16 | prog_num), data = pid>

	std::map<prog_num_t, PMTInstance *> m_PmtInstances;
};

#endif /* __PMT_PARSER_H__ */
