#include "DTVmwType.h"
#include "PATParser.h"

//------------------------------------------------------------------
// PAT
#define PAT_UNTIL_LAST_SECTION_NUMBER_LEN		(9)
#define PAT_PN_PID_LEN							(4)
#define PAT_program_number(BUFFER,N)		((BUFFER[4*(N)]<<8)+(BUFFER[4*(N)+1]))
#define PAT_program_map_PID(BUFFER,N)	((((BUFFER[4*(N)+2])&0x1F)<<8)+(BUFFER[4*(N)+3]))

//==================================================================


/*!
\brief		TCPATParser�� ������.
\param[in]	pTask	Task ������(PCTask*).
			TCSIManagerBase::EVENT_TIMEOUT  Alarm �̺�Ʈ�� ���� �� �ִ� Task Pointer.
\return		None
\remarks
\par        Example:
\code
\endcode
\see		TCPATParser::~TCPATParser()
*/
TCPATParser::TCPATParser()
: TCSectionParser(TABLE_ID, NULL)
{
	m_transportStreamId = 0;
	m_networkPID = INFINITY;
}




/*!
\brief		TCPATParser�� �Ҹ���.
\param[in]	None
\return		None
\remarks
\par        Example:
\code
\endcode
\see		TCPATParser::TCPATParser(PCTask* pTask)
*/
TCPATParser::~TCPATParser()
{
	//if (m_programList.FlagCreate())
	{
		Initialize();
		//m_programList.Destroy();
	}
}




bool TCPATParser::t_Create(void)
{
	//return m_programList.Create();
	return true;
}



/*
\brief
\par        Example:
\code
\endcode
\see
*/
void TCPATParser::t_Initialize(void)
{
	TCBaseSection::InitSection();
	DeleteAll();
}


/*!
\brief		ProgramNumber�� PMT PID�� �����ϰ� �ִ� ���α׷� ����Ʈ ����
\param[in]	None
\return		None
\remarks    Parser�� ���� �߰��� ���α׷� ����Ʈ�� �����Ѵ�.
\par        Example:
\code
			TCPATParser patParser;
			patParser.DeleteAll();
\endcode
\see		TCPATParser::TCPATParser(PCTask* pTask)
*/
void TCPATParser::DeleteAll(void)
{
	m_transportStreamId = 0;
	m_networkPID = INFINITY;
	m_programMap.clear();
	//if (m_programList.FlagCreate())
	//{
	//	DELETE_SORTED_LIST(TTProgramList, m_programList);
	//}
}

bool TCPATParser::t_Parse(unsigned char* pData, int size)
{
	//��۱����� �߸� �����ִ��� �����Ѵ�.
	/*if (t_privateIndicator == 1) // must be 1
	{
		DeleteAll();

		return false;
	}*/
	printf("[%s] data %p size %d\n", __FUNCTION__, pData, size);

	// Multi Section
	//BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::INFO, "TCPATParser::t_Parse Callded, CRC[%x]",crc32);
	switch(t_CheckVersion(t_versionNumber, t_sectionNumber, t_lastSectionNumber, t_crc))
	{
		case TABLE_INITIAL:
		case TABLE_CHANGE:
		case TABLE_APPEND:
			{
				//BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::DEBUGGING, "TCPATParser::t_Parse Table Changed, CRC[%x]", crc32);
				m_transportStreamId    = t_tableIdExtension;

				for (int a = 0; a < ((t_sectionLength - PAT_UNTIL_LAST_SECTION_NUMBER_LEN) / PAT_PN_PID_LEN); a++)
				{
					t_AddProgram(PAT_program_number(pData, a), PAT_program_map_PID(pData, a));

					BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::INFO, "Program Number[%d] ", PAT_program_number(pData, a));
					BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::INFO, "PMT PID[%d]\n", PAT_program_map_PID(pData, a));
				}
				return IsValid();
			}
		case TABLE_IGNORE :
			{
				//BP_PRINT(CCDebugBP::M_DTV,CCDebugBP::WARNING,"PAT Section Ignored... \n");
			}
			break;
		default:
			break;
	}

	return false;
}

int TCPATParser::NumOfProgramList(void)
{
	//return m_programList.Size();
	return m_programMap.size();
}

TTPN TCPATParser::ProgramNumber(int index)
{
	if (index >= m_programMap.size()) {
		return (TTPN)INFINITY;
	}

	int curr = 0;
	auto it = m_programMap.begin();
	while (it != m_programMap.end()) {
		if (index == curr++) {
			return (TTPN)it->first;
		}
		it++;
	}

	return (TTPN)INFINITY;
}

TTPID TCPATParser::ProgramPID(TTPN programNumber)
{
	auto it = m_programMap.find(programNumber);
	if (it == m_programMap.end()) {
		printf("[ProgramPID] pn %d -> PID_INVALID\n", programNumber);
		return PID_INVALID;
	}

	printf("[ProgramPID] pn %d -> pmt pid 0x%x\n", programNumber, it->second);
	return it->second;
}




/*
\brief      program ������ �߰��Ѵ�.
\pre
\post
\exception
\param[in]  programNumber    program_number
\param[in]  programPID       program_PID
\return
\remarks    program_number�� program_PID�� �߰��Ѵ�.
\par        Example:
\code
\endcode
\see
*/
void TCPATParser::t_AddProgram(TTPN programNumber, TTPID programPID)
{
	printf("[%s] prog %d, pid 0x%x\n", __FUNCTION__, programNumber, programPID);
	// program number 0x0000 is reserved to specify the network PID
	// PMT monitoring�� ���� �ʴ´�.
	// Network PID�� ��쿡�� ProgramList�� �������� �ʰ� ���� �����Ѵ�. Program map PID�� ��쿡�� ProgramList�� ����.
	if ( programNumber == TCPATParser::NETWORK_PID)
	{
		BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::INFO, "Program Number is ZERO!!(SIT..)\n");
		m_networkPID = programPID;
		return ;
	}

	m_programMap[programNumber] = programPID;
}

/*!
\brief      PAT �� Transport Stream Id�� �����Ѵ�.
\param[in]  None
\return		Transport Stream ID
\remarks    PAT �� Transport Stream Id�� �����Ѵ�.
\par        Example:
\code
			TCPATParser patParser;
			bool ret = patParser.Parse(patPid, pSectionData, TCWindow::WINDOW_MAIN)
			if(ret)
			{
				// Transport Stream Id�� ����.
				TTTSID tsid = patParser.TransportStreamId();
			}
\endcode
\see        TTPN TCPATParser::ProgramNumber(int index)
*/
TTTSID TCPATParser::TansportStreamId(void)
{
	return m_transportStreamId;
}

/*!
\brief		Network PID�� �����Ѵ�.
\param[in]  None
\return		Network PID
\remarks    Network PID�� �����Ѵ�.
\par        Example:
\code
			TCPATParser patParser;
			bool ret = patParser.Parse(patPid, pSectionData, TCWindow::WINDOW_MAIN)
			if(ret)
			{
				// Network Pid�� ����.
				TTPID networkPid = patParser.NetworkPID();
			}
\endcode
\see        TTPN TCPATParser::ProgramNumber(int index)
*/
TTPID TCPATParser::NetworkPID(void)
{
	return m_networkPID;
}

/*!
\brief		PAT�� �޾Ҵ��� ���θ� �����Ѵ�.
\param[in]  None
\return		��� PAT�� �� �޾����� True, �׷��� ������ false
\remarks    ��� PAT�� �� �޾Ҵ����� ���θ� �����Ѵ�. PAT�� Multi Section ���� ���ü� �����Ƿ� ���� Multi Section����
			���´ٸ� ���� Section Data�� �� �޾ƾ� True�� �����ϰ� �ȴ�.
\par        Example:
\code
			TCPATParser patParser;
			bool ret = patParser.Parse(patPid, pSectionData, TCWindow::WINDOW_MAIN)
			if(ret)
			{
				if(patParser.IsRecv())
				{
					// ��� PAT�� �� �޾������� ó��..
				}
			}
\endcode
\see        bool TCBaseSection::IsValid(void)
*/
bool  TCPATParser::IsRecv(void)
{
	bool ret=false;
	ret = TCSectionParser::IsRecv();
	if(ret) {
		ret= IsValid();
	}

	return ret;
}

bool TCPATParser::SaveSection(Section *pSection)
{
    return TCBaseSection::SaveSection(pSection);
}

bool TCPATParser::ListSection(std::vector<Section *> &sectionList)
{
    int sectionNumber = 0;
    int lastSectionNumber = 0;
    Section *pSection = NULL;

    if (IsRecv())
    {
        lastSectionNumber = LastSectionNum();
        for (sectionNumber = 0; sectionNumber <= lastSectionNumber; sectionNumber++)
        {
            if (GetSection(sectionNumber, &pSection))
            {
                sectionList.push_back(pSection);
            }
        }
    }
    else
    {
        printf("PAT not recv\n");
    }

    return (!sectionList.empty());
}
