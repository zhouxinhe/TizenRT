#include "Mpeg2TsTypes.h"
#include "PMTElementary.h"
#include "PMTInstance.h"
#include "PMTParser.h"

#define PMT_PROG_INFO_LENGTH(buffer)       (((buffer[0] & 0x0F) << 8) + buffer[1])
#define LENGTH_FIELD_BYTES                 (2)

#define PMT_PCR_PID(buffer)                (((buffer[0] & 0x1F) << 8) + buffer[1])
#define PID_FIELD_BYTES                    (2)

#define PMT_CRC_BYTES                      (4)

bool PMTInstance::m_Parse(uint8_t *pData, uint32_t size)
{
	m_programInfoLength = PMT_PROG_INFO_LENGTH(pData);
	pData += LENGTH_FIELD_BYTES;
	size -= LENGTH_FIELD_BYTES;

	if (m_programInfoLength + (uint32_t)PMT_CRC_BYTES <=  size) {
		// Ignore program info descriptors
		pData += m_programInfoLength;
		int length = (int)(size - m_programInfoLength - PMT_CRC_BYTES);
		int len = 0;
		while (length > 0) {
			PMTElementary *stream = new PMTElementary();
			assert(stream != NULL);
			len = stream->Parse(pData);
			m_streamList.push_back(stream);

			length -= len;
			pData  += len;
		}
	} else {
		meddbg("m_programInfoLength=%d invalid\n", m_programInfoLength);
		return false;
	}

	return true;
}

PMTInstance::PMTInstance()
{
	m_pid           = (ts_pid_t)INFINITY;
	m_programNumber = (prog_num_t)INFINITY;
	m_pcrPID        = (ts_pid_t)INFINITY;
	m_programInfoLength = 0;

	m_versionNumber = 0;
	m_currentNextIndicator = false;
	m_sectionNumber = 0;
	m_lastSectionNumber = 0;
}

PMTInstance::~PMTInstance(void)
{
	DeleteAll();

	m_streamList.clear();
}

bool PMTInstance::Create(ts_pid_t Pid)
{
	m_pid = Pid;
	return true;
}

void PMTInstance::DeleteAll(void)
{
	m_streamList.clear();
	m_programInfoLength = 0;
}

size_t PMTInstance::NumOfElementary(void)
{
	return m_streamList.size();
}

bool PMTInstance::Parse(uint8_t *pData, uint32_t size, prog_num_t programNum,
						int8_t versionNumber, uint8_t sectionNumber,
						uint8_t lastSectionNumber, uint32_t crc32, bool currentNextIndicator)
{
	m_programNumber         = programNum;
	m_versionNumber         = versionNumber;
	m_currentNextIndicator  = currentNextIndicator;
	m_sectionNumber         = sectionNumber;
	m_lastSectionNumber     = lastSectionNumber;
	m_pcrPID                = PMT_PCR_PID(pData);
	pData += PID_FIELD_BYTES;
	size -= PID_FIELD_BYTES;

	switch (t_CheckVersion(m_versionNumber, m_sectionNumber, m_lastSectionNumber, crc32)) {
	case TABLE_CHANGE:
	case TABLE_INITIAL:
	case TABLE_APPEND:
		m_Parse(pData, size);
		return IsValid();

	case TABLE_IGNORE :
		medwdbg("PMT Section Ignored...\n");
		break;

	default:
		break;
	}

	return false;
}

PMTElementary *PMTInstance::GetPMTElementary(uint32_t index)
{
	if ((size_t)index >= m_streamList.size()) {
		return NULL;
	}

	return m_streamList[index];
}
