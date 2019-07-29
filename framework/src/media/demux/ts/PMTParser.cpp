
#include "Section.h"
#include "PMTParser.h"
#include "PMTInstance.h"

/*!
\brief		TCPMTParser�� ������.
\param[in]	pTask	Task ������(PCTask*). TCSIManagerBase::EVENT_TIMEOUT  Alarm �̺�Ʈ�� ���� �� �ִ� Task Pointer.
\return		None
\remarks
\par        Example:
\code
\endcode
\see		TCPMTParser::~TCPMTParser()
*/
TCPMTParser::TCPMTParser()
: TCSectionParser(TABLE_ID, NULL)
{
	m_programNumber = (TTPN)INFINITY;
}


/*!
\brief		TCPMTParser�� �Ҹ���.
\param[in]	None
\return		None
\remarks
\par        Example:
\code
\endcode
\see		TCPMTParser::TCPMTParser(PCTask* pTask)
*/
TCPMTParser::~TCPMTParser()
{
	Initialize();
}

bool TCPMTParser::t_Create(void)
{
	m_PMTElements.clear();
	return true;
}

/*
\brief      delete the PMT information
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
void TCPMTParser::t_Initialize(void)
{
	m_programNumber = (TTPN)INFINITY;

	auto it = t_pmtInstanceHash.begin();
	while(it != t_pmtInstanceHash.end())
	{
		delete it->second;
		++it;
	}
	t_pmtInstanceHash.clear();
	m_PMTElements.clear();
}

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
bool TCPMTParser::t_Parse(unsigned char* pData, int size)
{
	m_programNumber = (TTPN)INFINITY;

	if (!m_PMTElements.empty()) {
		std::map<int, int>::iterator pmt_it;
		pmt_it = m_PMTElements.find(PMTKey(t_pid, t_tableIdExtension));	// key = pid<<16 |progNum, data = pid.
		if(pmt_it == m_PMTElements.end())
		{
			return false;	// PAT��  ����Ű�� PMT�� �ƴ� ��쿡�� monitor���� ����.
		}
	}

	// table id extension filed is program nubmer in PMT
	m_programNumber = t_tableIdExtension;


	TCPMTInstance* pInstance = t_pmtInstanceHash[m_programNumber];
	if (pInstance == NULL) {
		pInstance = new TCPMTInstance();
		INT_ASSERT(pInstance);
		pInstance->Create(t_pid);

		// add PMT instance
		t_pmtInstanceHash[m_programNumber] = pInstance;
        printf("add pmt instance: programnumber %d, pid 0x%x\n", m_programNumber, t_pid);
	}

	bool ret = pInstance->Parse(pData, size, t_tableIdExtension,
							t_versionNumber, t_sectionNumber,
							t_lastSectionNumber,t_crc,
							t_currentNextIndicator);

	return ret;
}


/*!
\brief		���� ������ Section�� ���� Program Number�� ��ȯ��.
\param[in]	None
\return		���� ������ Section�� ���� Program Number�� ��ȯ��.
\remarks
\par		Example:
\code
			TCPMTParser pmtParser;
			bool ret = pmtParser.Parse(pmtPid, pSectionData, TCWindow::WINDOW_MAIN);
			if(ret)
			{
				TTPN progNumber = pmtParser.ProgramNumber();
			}
\endcode
\see
*/
TTPN TCPMTParser::ProgramNumber(void)
{
	return m_programNumber;
}

/*!
\brief		PMT Instance�� ������ �����Ѵ�.
\param[in]	None
\return		PMT Instance�� ����
\remarks    PMT Instance�� �Ѱ��� PMT �� �����ϴ� ��ü�̴�.
			����, PMT Instance�� ������ �� PMT�� �����̴�. ��, �� PTC�� ä���� 3�� �ִٸ� PMT�� 3���� �Ǵ°��̰�,
			PMT Instance �� ������ ���� 3 �̵ȴ�.
\par        Example:
\code
			TCPMTParser pmtParser;
			bool ret = pmtParser.Parse(pmtPid, pSectionData, TCWindow::WINDOW_MAIN);
			if(ret)
			{
				int numOfPMT = pmtParser.NumOfPMTInstance();
			}
\endcode
\see
*/
int TCPMTParser::NumOfPMTInstance(void)
{
	return t_pmtInstanceHash.size();
}

/*!
\brief		Program Number�� �ش��ϴ� PMT Instance�� ��ȯ�Ѵ�.
\param[in]	programNumber(TTPN) ProgramNumber
\return		TCPMTInstance* PMTInstance ������
\remarks    ������ PMT�� PMT Instance Hash Table�� �����Ǵµ�,
			�� �Լ��� Program Number�� �ش��ϴ� PMT Instance�� ��ȯ�Ѵ�.
\par        Example:
\code
			TCPMTParser pmtParser;
			bool ret = pmtParser.Parse(pmtPid, pSectionData, TCWindow::WINDOW_MAIN);
			if(ret)
			{
				//Program Number�� 1 �� PMT Instance�� �����Ѵ�.
				TCPMTInstance* pmtInstance = pmtParser.PMTInstance(1);
			}
\endcode
\see
*/
TCPMTInstance* TCPMTParser::PMTInstance(TTPN programNumber)
{
	auto it = t_pmtInstanceHash.find(programNumber);
	if(it != t_pmtInstanceHash.end())
	{
		return it->second;
	}

    return NULL;
}

#if 1
/*!
\brief		Input ���ڷ� ���� index �� �ش��ϴ� PMT Instance�� ��ȯ�Ѵ�.
\param[in]	index(unsigned int) PMT Instance Hash �� Index
\return		TCPMTInstance* index �� �ش��ϴ� PMT Instance�� ã������, PMTInstance ������.
			ã�� �������� NULL Pointer
\remarks    ������ PMT�� PMT Instance Hash Table�� �����Ǵµ�,
			�� �Լ��� Hash Table�� Index�� �ش��ϴ� PMT Instance�� ��ȯ�Ѵ�.
\par		Example:
\code
			TCPMTParser pmtParser;
			bool ret = pmtParser.Parse(pmtPid, pSectionData, TCWindow::WINDOW_MAIN);
			if(ret)
			{
				//PMT Instance Hash Table���� ù��°�� ����� PMT Instance �� ��ȯ�Ѵ�.
				TCPMTInstance* pmtInstance = pmtParser.PMTInstance(0);
			}
\endcode
\see
*/
TCPMTInstance* TCPMTParser::PMTInstanceOfIndex(unsigned int index)
{
	std::map<TTPN, TCPMTInstance*>::iterator it;
	it = t_pmtInstanceHash.begin();
	unsigned int ii = 0;
	while(it != t_pmtInstanceHash.end() && ii != index)
	{
		++ii;
		++it;
	}

	if (it != t_pmtInstanceHash.end())
	{
		return it->second;
	}

	return NULL;
}
#endif

/*!
\brief		PMTParser���� parsing�� element�� update�Ѵ�.
\param[in] 	PMTElements
\return
\remarks
\par		Example:
\code
\endcode
\see
*/
void TCPMTParser::UpdatePMTElements(std::map<int, int>& pmtMap)
{
	m_PMTElements = pmtMap;
}

/*!
\brief		PMT element�� ��� clear��.
\param[in] 	PMTElements
\return
\remarks
\par		Example:
\code
\endcode
\see
*/

void TCPMTParser::ClearPMTElements(void)
{
	m_PMTElements.clear();
}

bool TCPMTParser::SaveSection(Section* pSection)
{
    if (m_programNumber == (TTPN)INFINITY)
        return false;

	TCPMTInstance* pInstance = t_pmtInstanceHash[m_programNumber];
	if (pInstance == NULL)
	{
        printf("no mpt instance: program number %d\n", m_programNumber);
        return false;
	}

    return pInstance->SaveSection(pSection);
}

bool TCPMTParser::ListSection(std::vector<Section*>& sectionList)
{
    int i;
    int sectionNumber = 0;
    int lastSectionNumber = 0;
    int numOfInstance = NumOfPMTInstance();
    TCPMTInstance* pPMTInstance = NULL;
    Section* pSection = NULL;

    for (i = 0; i < numOfInstance; i++)
    {
        pPMTInstance = PMTInstanceOfIndex(i);
        lastSectionNumber = pPMTInstance->LastSectionNum();

        for (sectionNumber = 0; sectionNumber <= lastSectionNumber; sectionNumber++)
        {
            if (pPMTInstance->GetSection(sectionNumber, &pSection))
            {
                sectionList.push_back(pSection);
            }
        }
    }

    return (!sectionList.empty());
}

int TCPMTParser::PMTKey(int Pid, int ProgNum)
{
	return ((Pid<<16) | ProgNum);
}

