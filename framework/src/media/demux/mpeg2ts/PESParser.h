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

#ifndef __PES_PARSER_H__
#define __PES_PARSER_H__

#include "Mpeg2TsTypes.h"


class PESParser
{
public:
	PESParser();
	virtual ~PESParser();

	bool  Parse(uint8_t *pData, size_t dataLength);
	ts_pid_t Pid(void)  { return t_pid; }
	uint8_t *ESData(void);
	size_t ESDataLength(void);
	bool IsValid(void);
	bool Init(void);

	//virtual PESParser& operator=(const PESParser& parser);
private:
	ts_pid_t t_pid;
	uint8_t *t_pPESData;
	uint32_t m_start_code_prefix;
	uint8_t m_stream_id;
	uint16_t m_packet_length;
	/// for audio streams
	//{ optional PES header
	uint8_t m_fixed_01                 : 2;
	uint8_t m_pes_scrambling_control   : 2;
	uint8_t m_pes_priority             : 1;
	uint8_t m_data_alignment_indicator : 1;
	uint8_t m_copyright                : 1;
	uint8_t m_original_or_copy         : 1;
	// 7 flags
	uint8_t m_pts_dts_flags             : 2;
	uint8_t m_escr_flag                 : 1;
	uint8_t m_es_rate_flag              : 1;
	uint8_t m_dsm_trick_mode_flag       : 1;
	uint8_t m_additional_copy_info_flag : 1;
	uint8_t m_pes_crc_flag              : 1;
	uint8_t m_pes_extension_flag        : 1;
	// following header length
	uint8_t m_pes_header_data_length;
	//optional fields ...
	//} optional PES header

	// process the pes data.
	bool t_Parse(uint8_t *pData, uint32_t size);
};

#endif /* __PES_PARSER_H__ */
