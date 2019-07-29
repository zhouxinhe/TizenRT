#include "DTVmwType.h"
//#include "MW.h"
//#include "BaseDesc.h"
#include "Section.h"
#include "BaseSection.h"
#include "SectionParser.h"
//#include "ParseManager.h"


//------------------------------------------------------------------
// SECTION INFO
#define SI_TID_NUM_OF_BYTE            1
#define SI_SECTION_LENGTH_NUM_OF_BYTE 2
#define SI_RSV1(BUFFER)      ((BUFFER[1]>>4)&0x03)
#define SI_TIDE(BUFFER)      ((BUFFER[3]<<8)+BUFFER[4])
#define SI_TSID(BUFFER)      ((BUFFER[3]<<8)+BUFFER[4])
#define SI_PN(BUFFER)        ((BUFFER[3]<<8)+BUFFER[4])
#define SI_SID(BUFFER)       ((BUFFER[3]<<8)+BUFFER[4])
#define SI_RR(BUFFER)        (BUFFER[4])
#define SI_RSV2(BUFFER)      ((BUFFER[5]>>6)&0x03)// si codereview 070725
#define SI_VN(BUFFER)        ((BUFFER[5]>>1)&0x1F)
#define SI_CNI(BUFFER)       (BUFFER[5]&0x01)
#define SI_SN(BUFFER)        (BUFFER[6])
#define SI_LSN(BUFFER)       (BUFFER[7])
#define SI_CRC(BUFFER,LEN)		( (BUFFER[(LEN)-4]<<24)+(BUFFER[(LEN)-3]<<16)+ \
									(BUFFER[(LEN)-2]<<8)+(BUFFER[(LEN)-1]) )
#define PSIP_PV(BUFFER)        (BUFFER[8])
#define PSI_DATA(BUFFER)       (&(BUFFER[8])) // 8 = SECTION_HEADER_LENGTH + LONG_FORM_HEADER_LENGTH
#define PSIP_DATA(BUFFER)      (&(BUFFER[9]))
#define SHORT_FORM(BUFFER)		(&(BUFFER[3]))
#define LONG_FORM(BUFFER)		(&(BUFFER[9]))
//==================================================================

/*!
\brief      TCSectionParser �� ������.
\param[in]  tableId(int)
\param[in]  pTask(PCTask*) TCSIManagerBase::EVENT_TIMEOUT  Alarm �̺�Ʈ�� ���� �� �ִ� Task Pointer.
\return     None
\remarks
\par        Example:
\code
\endcode
\see
*/
TCSectionParser::TCSectionParser(int tableId, void* pTask)
{
	t_tableId       = tableId;
	//m_pTask         = pTask;
	//m_interval      = 0;
	//m_bTimeOut      = false;
	m_bRecv         = false;
	t_pSectionData  = NULL;
	t_sectionLength = 0;

	t_sectionSyntaxIndicator = false;
	t_privateIndicator = false;
	t_tableIdExtension = 0;
	t_currentNextIndicator = 0;
	t_sectionNumber = 0;
	t_lastSectionNumber = 0;
	t_protocolVersion = 0;
	t_crc = 0;
}

/*!
\brief      TCSectionParser �� �Ҹ���.
\param[in]  tableId(int)
\param[in]  pTask(PCTask*) TCSIManagerBase::EVENT_TIMEOUT  Alarm �̺�Ʈ�� ���� �� �ִ� Task Pointer.
\return     None
\remarks
\par        Example:
\code
\endcode
\see
*/
TCSectionParser::~TCSectionParser()
{
//	if (PCAlarm::FlagCreate())
//	{
//		PCAlarm::Destroy();
//	}
}

/*!
\brief      TCSectionParser�� ��ӹ��� ������ Parser(PAT, PMT��)�� t_Create()�� ȣ���Ͽ�
			��� ����, ����Ʈ���� ���� �� �ʱ�ȭ�� �����Ѵ�.
\param[in]  None
\return     t_Create() ���� ����
\remarks
\par        Example:
\code
			PATParser patParser;
			patParser.Create();
\endcode
\see
*/

bool TCSectionParser::Create(void)
{
	return t_Create();
}

/*!
\brief      TCSectionParser�� ��ӹ��� ������ Parser(PAT, PMT��)�� t_Initialize()�� ȣ���Ͽ�
			��� ����, ����Ʈ���� ���� �� �ʱ�ȭ�� �����Ѵ�.
\param[in]  None
\return     None
\remarks
\par        Example:
\code
			PATParser patParser;
			patParser.Initialize();
\endcode
\see
*/
void TCSectionParser::Initialize(void)
{
	t_Initialize();

	m_bRecv = false;
	t_pSectionData = NULL;
	t_sectionLength = 0;// si codereview 070725

	return;
}

/*!
\brief      Section Data�� Parsing �Ѵ�.
\param[in]  pid(short)		Packet Identifier
\param[in]  pData(char*)	Section Data�� �ּ�
			- TCWindow::WINDOW_MAIN
			- TCWindow::WINDOW_VIRTUAL1
\return     None
\remarks
\par        Example:
\code
			TCPATParser patParser;
			patParser.Create();
			bool ret = patParser.Parse(0x00, pSectionData, TCWindow::WINDOW_MAIN);
			if(ret)
			{
				//�������� SectionData�� ���� ���������� Parsing �� ���..
			}



\endcode
\see
*/
bool TCSectionParser::Parse(short pid, unsigned char* pData)
{
	m_bRecv                  = true;

	t_pid                    = pid;
	t_pSectionData           = pData;
	t_tableId                = SI_table_id(pData);
	t_sectionSyntaxIndicator = SI_section_syntax_indicator(pData);
	t_privateIndicator       = SI_private_indicator(pData);
	t_sectionLength          = SI_section_length(pData);

	if (t_sectionSyntaxIndicator)
	{
		//Long form
		t_tableIdExtension     = SI_TSID(pData);
		t_versionNumber        = SI_VN(pData);
		t_currentNextIndicator = SI_CNI(pData);
		t_sectionNumber        = SI_SN(pData);
		t_lastSectionNumber    = SI_LSN(pData);
		t_crc                  = SI_CRC(pData,t_sectionLength+SECTION_HEADER_LENGTH);
#ifdef config_psip
		if (t_CheckPSIPTable(t_tableId))
		{
			t_protocolVersion      = PSIP_PV(pData);
			if( t_protocolVersion != 0 || t_currentNextIndicator != 1)//invalid check
			{
				//BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::WARNING,"Protocol_Version error tid=0x%x, pv=%d, cnid[%d]",
				//	t_tableId,t_protocolVersion, t_currentNextIndicator);
				return false;
			}
			return t_Parse(PSIP_DATA(pData), t_sectionLength - TCSectionParser::PSIP_HEADER_LENGTH);
		}
		else
#endif
		{
			return t_Parse(PSI_DATA(pData), t_sectionLength - TCSectionParser::LONG_FORM_HEADER_LENGTH);
		}
	}
	else
	{
		//short form
		return t_Parse(SHORT_FORM(pData), t_sectionLength);
	}
}

bool TCSectionParser::t_CheckPSIPTable(unsigned char tableId)
{
	return false;
}


#if 0
bool TCSectionParser::t_OnAlarm(const PTEvent *event)
{
	if (t_PCTask() == NULL)
	{
		return false;
	}

	m_bTimeOut = true;

	PTEvent ev;
	ev.receiver = t_PCTask();
	ev.type     = CParserManager::EVENT_TIMEOUT;
	ev.param.l[0] = t_tableId;

	return PCTask::Send(&ev);
}
#endif

#if 0
/*!
\brief      TCSectionParser �� �����ڿ��� ������ Task �� ����  Alarm �� Reset �Ѵ�.
\param[in]  interval(int)
\return     interval �� 0���� ũ�� true , 0���� ������ false
\remarks
\par        Example:
\code
\endcode
\see
*/
bool TCSectionParser::ResetTimer(int interval)
{
	m_bTimeOut = false;
	if (interval > 0)
	{
		m_interval = interval;

		if (PCAlarm::FlagCreate())
		{
			PCAlarm::Reset(m_interval, 1);
		}
		else
		{
			PCAlarm::Create(t_PCTask(), m_interval, 1);
		}
		return true;
	}

	return false;
}
#endif

#if 0
/*!
\brief      TCSectionParser �� �����ڿ��� ������ Task �� ����  Alarm �� Stop �Ѵ�.
\param[in]  interval(int)
\return     interval �� 0���� ũ�� true , 0���� ������ false
\remarks
\par        Example:
\code
\endcode
\see
*/
bool TCSectionParser::StopTimer(void)
{
	if (PCAlarm::FlagCreate())
	{
		PCAlarm::Reset(m_interval, 0);
		return true;
	}
	return false;
}
#endif

/*!
\brief      TCSectionParser �� Operator= Override.
\param[in]  parser(const TCSectionParser&)
\return     TCSectionParser �� ���� reference
\remarks
\par        Example:
\code
\endcode
\see
*/
TCSectionParser& TCSectionParser::operator=(const TCSectionParser& parser)
{
	t_pSectionData = parser.t_pSectionData;
	t_pid = parser.t_pid;
	t_tableId = parser.t_tableId;
	t_sectionSyntaxIndicator = parser.t_sectionSyntaxIndicator;
	t_privateIndicator = parser.t_privateIndicator;
	t_sectionLength = parser.t_sectionLength;
	t_tableIdExtension = parser.t_tableIdExtension;
	t_versionNumber = parser.t_versionNumber;
	t_currentNextIndicator = parser.t_currentNextIndicator;
	t_sectionNumber = parser.t_sectionNumber;
	t_lastSectionNumber = parser.t_lastSectionNumber;
	t_protocolVersion = parser.t_protocolVersion;
	t_crc = parser.t_crc;
	return *this;
}

