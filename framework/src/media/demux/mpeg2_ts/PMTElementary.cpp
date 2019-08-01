#include "DTVmwType.h"
#include "PMTElementary.h"
//#include "Descriptor.h"
#include "PMTParser.h"

#define ES_BODY_LEN					(5)
#define PMT_stream_type(BUFFER)         (BUFFER[0])
#define PMT_elementary_PID(BUFFER)      (((BUFFER[1]&0x1F)<<8)+BUFFER[2])
#define PMT_ES_info_length(BUFFER)      (((BUFFER[3]&0x0F)<<8)+BUFFER[4])

/*!
\brief		TCPMTElementary�� ������.
\param[in]	None
\return		None
\remarks    TCPMTElementary�� ������.
\par		Example:
\code
\endcode
\see		TCPMTElementary::~TCPMTElementary()
*/
TCPMTElementary::TCPMTElementary()
{
	m_elementary_PID = INFINITY;
	m_streamType = 0;
	m_esInfoLength = 0;
}

/*!
\brief		TCPMTElementary�� �Ҹ���.
\param[in]	None
\return		None
\remarks    TCPMTElementary�� �Ҹ���. ��� �������� Destroy �Ѵ�.
\par		Example:
\code
\endcode
\see		TCPMTElementary::TCPMTElementary()
*/
TCPMTElementary::~TCPMTElementary()
{
	//m_descriptorHash.Destroy();
}

/*!
\brief		TCPMTElementary���� ����ϴ�, List���� ��������� �����Ѵ�.
\param[in]	None
\return		bool
			ES Loop ���� Descriptor���� �����ϱ� ���� List�� ���� ����/���� ����.
\remarks	TCPMTElementary���� ����ϴ�, List���� ��������� �����Ѵ�.
\par		Example:
\code
			TCPMTElementary TCPMTElementary;
			TCPMTElementary.Create();
\endcode
\see		TCPMTElementary::TCPMTElementary()
*/
bool TCPMTElementary::Create(void)
{
	return true;//m_descriptorHash.Create(TCDescriptor::DEFAULT_NUM_OF_DESC);
}

/*!
\brief      PMT Elementary Stream �� Stream Type�� ��ȯȯ��.
\param[in]  None
\return     ES StreamType
			- TCDescServiceLocation::DSP_SIM_ISO11172_2_VIDEO
			- TCDescServiceLocation::DSP_SIM_MPEG2_VIDEO:
			- TCDescServiceLocation::DSP_SIM_AUDIO_AC3
			- TCDescServiceLocation::DSP_SIM_AUDIO_MPEG1
			- TCDescServiceLocation::DSP_SIM_AUDIO_MPEG2
\remarks
\par        Example:
\code
			TCPATParser patParser;
			bool ret = patParser.Parse(patPid, pSectionData, TCWindow::WINDOW_MAIN)
			if(ret)
			{
				TCPMTParser pmtParser;

				bool ret = pmtParser.Parse(pmtPid, pSectionData, TCWindow::WINDOW_MAIN);
				if(ret)
				{
					// PAT Parser���� ù��°�� ����� ProgramNumber�� ���� PMT Instance�� ��´�.
					TCPMTInstance* pPmtInstance = pPmtParser.PMTInstance(patParser.ProgramNumber(0));
					// PMT Instance���� ù��°�� ����� PMT Elementary�� ���´�.
					TCPMTElementary* pElementary = pPmtInstance->PMTElementary(0);
					if(pElementary)
						unsigned char streamType = pElementary->StreamType();

				}
			}
\endcode
\see
*/
unsigned char TCPMTElementary::StreamType(void)
{
	INT_ASSERT(m_elementary_PID != INFINITY);

	return m_streamType;
}

/*!
\brief      PMT Elementary Stream �� PID�� ��ȯ�Ѵ�.
\param[in]  None
\return     TTPID ES�� PID
\remarks    PMT Elementary Stream �� PID�� ��ȯ�Ѵ�.
\par        Example:
\code
			TCPMTParser pmtParser;
			bool ret = pmtParser.Parse(pmtPid, pSectionData, TCWindow::WINDOW_MAIN);
			if(ret)
			{
				TCPMTInstance* pPmtInstance = pPmtParser.PMTInstance(programNumber);

				for(int i = 0; i< pPmtInstance->NumOfElementary() ; i++)
				{
					TCPMTElementary* pElementary = pPmtInstance->PMTElementary(i);
					TTPID elementaryPID = pElementary->ElementaryPID();
				}
			}
\endcode
\see
*/
TTPID TCPMTElementary::ElementaryPID(void)
{
	INT_ASSERT(m_elementary_PID != INFINITY);

	return m_elementary_PID;
}

/*
\brief		PMT �� stream_type ������ �κ��� Paring �Ѵ�.
\param[in]	pData(unsigned char*) stream_type ������ Section Data
\return		ES_info_Length + 5(ES �κ�)
\remarks    PMT �� stream_type ������ �κ��� Paring �Ѵ�.
\par        Example:
\code
			TCPMTElementary elementary;
			elementary.Create();
			elementary.Parse(pSectionData);
\endcode
\see
*/
int TCPMTElementary::Parse(unsigned char* pData)
{
	//INT_ASSERT(m_descriptorHash.FlagCreate() != false);

	m_esInfoLength = PMT_ES_info_length(pData);

	m_streamType     = PMT_stream_type(pData);
	m_elementary_PID = PMT_elementary_PID(pData);

	// Ignore ES info descriptors
	//TCDescriptor desc;
	//desc.Parse(&pData[ES_BODY_LEN], m_esInfoLength, m_descriptorHash, TCPMTParser::TABLE_ID);
	return ES_BODY_LEN + m_esInfoLength;
}

