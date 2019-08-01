#include "DTVmwType.h"
//#include "PESPacket.h"
#include "PESParser.h"



PESParser::PESParser()
{
	Init();
}

PESParser::~PESParser()
{
}

bool PESParser::Parse(unsigned char* pData, size_t dataLength)
{
	assert(6 <= dataLength);
	t_pPESData          = pData;
	m_start_code_prefix = (pData[0] << 16) | (pData[1] << 8) | pData[2]; // TODO: use macro like SI_section_length
	m_stream_id         = (pData[3]);
	m_packet_length     = (pData[4] << 8) | pData[5];

	assert(m_start_code_prefix == PES_PACKET_START_CODE_PREFIX);
	assert(6 + m_packet_length <= dataLength);
	printf("[%s] stream_id: 0x%x, m_packet_length 0x%x(%d)\n", __FUNCTION__, m_stream_id, m_packet_length, m_packet_length);

	return t_Parse(&pData[6], m_packet_length);
}


bool PESParser::t_Parse(unsigned char* pData, int size)
{
	switch (m_stream_id) {
	case 0xc0 ... 0xdf: { // 110xxxxx means audio streams
		m_fixed_01                 = (pData[0] >> 6) & 0x3;
		m_pes_scrambling_control   = (pData[0] >> 4) & 0x3;
		m_pes_priority             = (pData[0] >> 3) & 0x1;
		m_data_alignment_indicator = (pData[0] >> 2) & 0x1;
		m_copyright                = (pData[0] >> 1) & 0x1;
		m_original_or_copy         = (pData[0]) & 0x1;

		m_pts_dts_flags             = (pData[1] >> 6) & 0x3;
		m_escr_flag                 = (pData[1] >> 5) & 0x1;
		m_es_rate_flag              = (pData[1] >> 4) & 0x1;
		m_dsm_trick_mode_flag       = (pData[1] >> 3) & 0x1;
		m_additional_copy_info_flag = (pData[1] >> 2) & 0x1;
		m_pes_crc_flag              = (pData[1] >> 1) & 0x1;
		m_pes_extension_flag        = (pData[1]) & 0x1;

		m_pes_header_data_length = pData[2];

		assert(m_fixed_01 == 0x2);
#if 0
		printf("[%s]\n"
			"m_pes_scrambling_control   %d\n"
			"m_pes_priority             %d\n"
			"m_data_alignment_indicator %d\n"
			"m_copyright                %d\n"
			"m_original_or_copy         %d\n"
			"m_pts_dts_flags             %d\n"
			"m_escr_flag                 %d\n"
			"m_es_rate_flag              %d\n"
			"m_dsm_trick_mode_flag       %d\n"
			"m_additional_copy_info_flag %d\n"
			"m_pes_crc_flag              %d\n"
			"m_pes_extension_flag        %d\n"
			"m_pes_header_data_length  %d\n\n",
			__FUNCTION__,
			m_pes_scrambling_control,
			m_pes_priority,
			m_data_alignment_indicator,
			m_copyright,
			m_original_or_copy,
			m_pts_dts_flags,
			m_escr_flag,
			m_es_rate_flag,
			m_dsm_trick_mode_flag,
			m_additional_copy_info_flag,
			m_pes_crc_flag,
			m_pes_extension_flag,
			m_pes_header_data_length);
#endif
		return true;
	}

	default:
		// not supported
		break;
	}

	return false;
}

unsigned char * PESParser::ESData(void)
{
	return t_pPESData + 6 + 3 + m_pes_header_data_length;
}

size_t PESParser::ESDataLength(void)
{
	return m_packet_length - 3 - m_pes_header_data_length;
}

bool PESParser::IsValid(void)
{
	return (m_start_code_prefix == PES_PACKET_START_CODE_PREFIX);
}

bool PESParser::Init(void)
{
	m_start_code_prefix = 0;
	t_pPESData  = NULL;
	m_packet_length = 0;
	t_pid = -1;

}

