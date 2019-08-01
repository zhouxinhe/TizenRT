#ifndef __PES_PARSER_H__
#define __PES_PARSER_H__

#include "DTVmwType.h"

#define PES_PACKET_START_CODE_PREFIX 0x000001

class PESParser
{
public:

	PESParser();
	virtual ~PESParser();

	bool  Parse(unsigned char* pData, size_t dataLength);
	short Pid(void)  { return t_pid; }
	unsigned char * ESData(void);
	size_t ESDataLength(void);
	bool IsValid(void);
	bool Init(void);

	//virtual PESParser& operator=(const PESParser& parser);
private:
	short t_pid;
	unsigned char *t_pPESData;
    unsigned int m_start_code_prefix;
    unsigned char m_stream_id;
	short m_packet_length;

	//if (m_stream_id == audio streams)
	//{ optional PES header
		unsigned char m_fixed_01                 : 2;
		unsigned char m_pes_scrambling_control   : 2;
		unsigned char m_pes_priority             : 1;
		unsigned char m_data_alignment_indicator : 1;
		unsigned char m_copyright                : 1;
		unsigned char m_original_or_copy         : 1;

		// 7 flags
		unsigned char m_pts_dts_flags             : 2;
		unsigned char m_escr_flag                 : 1;
		unsigned char m_es_rate_flag              : 1;
		unsigned char m_dsm_trick_mode_flag       : 1;
		unsigned char m_additional_copy_info_flag : 1;
		unsigned char m_pes_crc_flag              : 1;
		unsigned char m_pes_extension_flag        : 1;

		// the following header length
		unsigned char m_pes_header_data_length;

		//optional fields
		//if (m_pes_extension_flag)
		//{
//			unsigned char m_pes_private_data_flag        : 1;
//			unsigned char m_pack_header_field_flag       : 1;
//			unsigned char m_prog_packet_seq_counter_flag : 1;
//			unsigned char m_p_std_byffer_flag            : 1;
//			unsigned char m_reserved                     : 3;
//			unsigned char m_pes_extension_flag_2         : 1;
		//}

		//unsigned char m_stuffing_bytes;
	//} optional PES header
	//else ...

	// process the pes data.
	bool t_Parse(unsigned char* pData, int size);
};

#endif /* __PES_PARSER_H__ */
