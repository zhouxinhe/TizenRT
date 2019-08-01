#include "DTVmwType.h"
//#include "Descriptor.h"
#include "PMTElementary.h"
#include "PMTInstance.h"
#include "PMTParser.h"

#define DSP_SIM_TWO_BYTE                   (2)
#define PMT_CRC_SIZE                       (4)
#define PMT_PCR_PID(BUFFER)                (((BUFFER[0]&0x1F)<<8)+BUFFER[1])
#define PMT_program_info_length(BUFFER)    (((BUFFER[0]&0x0F)<<8)+BUFFER[1])

/*
\brief
\pre
\post
\exception
\param[in]
\return
\remarks
\par        Example:
\code
\endcode
\see
*/
bool TCPMTInstance::m_Parse(unsigned char* pData, int size)
{

	m_programInfoLength = PMT_program_info_length(pData);

	pData += DSP_SIM_TWO_BYTE;
	size -= DSP_SIM_TWO_BYTE;

	if(m_programInfoLength <=  size-PMT_CRC_SIZE)
	{
		// Ignore program info descriptors
		//TCDescriptor desc;
		//desc.Parse(pData, m_programInfoLength, m_descriptorHash, TCPMTParser::TABLE_ID);
		int length = size - m_programInfoLength - PMT_CRC_SIZE;

		pData += m_programInfoLength;

		int len = 0;
		while(length > 0)
		{
			TCPMTElementary* stream = new TCPMTElementary();

			INT_ASSERT(stream != NULL);

			stream->Create();

			len = stream->Parse(pData);
			m_streamList.push_back(stream);

			length -= len;
			pData  += len;
		}
	}
	else
	{
		BP_PRINT(CCDebugBP::M_DTV, CCDebugBP::MAJOR, "TCPMTInstance::m_Parse, m_programInfoLength[%d] Error", m_programInfoLength);
		return false;
	}

	// si codereview 070731
	return true;
}



/*!
\brief		TCPMTInstance�� ������.
\param[in]	None
\return		None
\remarks    TCPMTInstance�� ������.
\par        Example:
\code
\endcode
\see		TCPMTInstance::~TCPMTInstance()
*/
TCPMTInstance::TCPMTInstance()
{
	m_pid           = INFINITY;
	m_programNumber = (unsigned short)INFINITY;
	m_pcrPID        = INFINITY;
	m_programInfoLength = 0;

	m_versionNumber = 0;
	m_currentNextIndicator = false;
	m_sectionNumber = 0;
	m_lastSectionNumber = 0;
}

/*!
\brief		TCPMTInstance�� �Ҹ���.
\param[in]	None
\return		None
\remarks    TCPMTInstance�� �Ҹ���. ��� �������� Destroy �Ѵ�.
\par        Example:
\code
\endcode
\see		TCPMTInstance::TCPMTInstance()
*/
TCPMTInstance::~TCPMTInstance(void)
{
	DeleteAll();

	m_streamList.clear();
	//m_descriptorHash.Destroy();
}

bool TCPMTInstance::Create(TTPID Pid)
{
	m_pid = Pid;
	return true;//m_descriptorHash.Create(TCDescriptor::DEFAULT_NUM_OF_DESC);
}

void TCPMTInstance::DeleteAll(void)
{
	DELETE_LIST(TCPMTElementary, m_streamList);
	//m_descriptorHash.DeleteAll();
	m_programInfoLength = 0;
}

TTPID TCPMTInstance::PCR_PID(void)
{
	return m_pcrPID;
}

int TCPMTInstance::NumOfElementary(void)
{
	return m_streamList.size();
}

bool TCPMTInstance::Parse(unsigned char* pData, int size, TTPN programNum,
						  char versionNumber, unsigned char sectionNumber,
						  unsigned char  lastSectionNumber, unsigned long crc32, bool currentNextIndicator)
{
	m_programNumber			= programNum;
	m_versionNumber         = versionNumber;
	m_currentNextIndicator  = currentNextIndicator;
	m_sectionNumber         = sectionNumber;
	m_lastSectionNumber     = lastSectionNumber;
	m_pcrPID                = PMT_PCR_PID(pData);
	pData += DSP_SIM_TWO_BYTE;
	size -= DSP_SIM_TWO_BYTE;

	//BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::INFO,"TCPMTInstance::Parse Called, CRC[%x]", crc32);
	switch(t_CheckVersion(m_versionNumber, m_sectionNumber, m_lastSectionNumber, crc32))
	{
		case TABLE_CHANGE:
		case TABLE_INITIAL:// si codereview 070731
		case TABLE_APPEND:
			{
				m_Parse(pData, size);
				return IsValid();
			}
		case TABLE_IGNORE :
			{
				BP_PRINT(CCDebugBP::M_DTV,CCDebugBP::WARNING,"PMT Section Ignored... ");
			}
			break;
		default:
			break;
	}

	return false;
}

TCPMTElementary* TCPMTInstance::PMTElementary(int elemIdx)
{
	if((unsigned long)elemIdx >= m_streamList.size()) {
		return NULL;
	}

	return (TCPMTElementary *)m_streamList[elemIdx];
}

