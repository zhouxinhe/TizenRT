#include <assert.h>
#include "DTVmwType.h"
#include "Section.h"
#include "SectionParser.h"
#include "TSParser.h"
#include "ParseManager.h"
#include "PMTInstance.h"
#include "PMTElementary.h"

//#include "DescLinkage.h"

#define DEFUALT_NUM_OF_TABLE_PARSER 2

using namespace std;



//CParserManager* CParserManager::m_pTableParse = NULL;

CParserManager::CParserManager()
{
    //t_tableParserHash.Create(DEFUALT_NUM_OF_TABLE_PARSER);
    // PAT
	t_AddParser(new TCPATParser());
    // PMT
	t_AddParser(new TCPMTParser());
}

CParserManager::~CParserManager()
{
	//DELETE_LIST(TCSectionParser, t_tableParserHash);
	// delete items in map
	t_tableParserHash.clear();
}

#if 0
void CParserManager::AddFilter(short pid, int tableId, int ms, unsigned char bVersion, int priority, int response_time, bool bCheckCRC)
{
	if (t_Monitor(pid, tableId, ms, bVersion, bCheckCRC))
	{
		bool bVer = (bVersion != 0) ? true : false;
		int dummy_handle;
		//t_filterManager.Start(pid, tableId, bVer, 0, false, bCheckCRC,(TCFilterManager::Priority)priority, response_time, &dummy_handle);
	}
}

bool CParserManager::RmvFilter(int tableId)
{
	if (t_StopMonitor(tableId))
	{
		//t_filterManager.Stop(tableId, 0);
	}

	return false;
}

bool CParserManager::RmvFilter(short pid, int tableId, unsigned char flag)
{
	if (t_StopMonitor(tableId))
	{
		//t_filterManager.Stop(pid, tableId, flag);
	}

	return true;
}
#endif

bool CParserManager::IsPatReceived(void)
{
	TCSectionParser* pTableParser = t_Parser(TCPATParser::TABLE_ID);
	if (pTableParser == NULL) {
		printf("[%s] no PAT parser\n", __FUNCTION__);
		return false;
	}

	TCPATParser *pPATParser = static_cast<TCPATParser*>(pTableParser);
	printf("[%s] return %d\n", __FUNCTION__, pPATParser->IsRecv());
	return pPATParser->IsRecv();
}

bool CParserManager::IsPmtReceived(TTPN progNum)
{
	TCSectionParser* pTableParser = t_Parser(TCPMTParser::TABLE_ID);
	if (pTableParser == NULL) {
		return false;
	}

	TCPMTParser *pPMTParser = static_cast<TCPMTParser*>(pTableParser);
	TCPMTInstance *pPMTInstance = pPMTParser->PMTInstance(progNum);
	if (pPMTInstance == NULL) {
		return false;
	}

	return pPMTInstance->IsValid();
}

bool CParserManager::IsPmtReceived(void)
{
	TCPATParser *pPATParser = static_cast<TCPATParser*>(t_Parser(TCPATParser::TABLE_ID));

	if (pPATParser && pPATParser->IsRecv()) {
		int i;
		int progs = pPATParser->NumOfProgramList();
		for (i = 0; i < progs; i++) {
			if (!IsPmtReceived(pPATParser->ProgramNumber(i))) {
				return false;
			}
		}

		return true;
	}

	return false;
}

bool CParserManager::GetAudioPESPid(TTPN progNum, TTPID &pid)
{
	pid = -1;

	TCPMTParser *pPMTParser = static_cast<TCPMTParser*>(t_Parser(TCPMTParser::TABLE_ID));
	TCPMTInstance *pPMTInstance = pPMTParser->PMTInstance(progNum);


	if (pPMTInstance && pPMTInstance->IsValid()) {
		int i;
		int num = pPMTInstance->NumOfElementary();
		for (i = 0; i < num; i++) {
			TCPMTElementary *pStream = pPMTInstance->PMTElementary(i);
			assert(pStream);
			switch (pStream->StreamType()) {
				case STREAM_TYPE_AUDIO_AAC:
				case STREAM_TYPE_AUDIO_MPEG2:
				case STREAM_TYPE_AUDIO_AC3:
				case STREAM_TYPE_AUDIO_MPEG1:
				case STREAM_TYPE_AUDIO_HE_AAC:
					pid = pStream->ElementaryPID();
					printf("[%s] stream type 0x%02x, pid 0x%x\n", __FUNCTION__, pStream->StreamType(), pid);
					break;
				case 0x15: //?
					break;
			}
		}
	}

	return (pid != -1);
}

bool CParserManager::GetPrograms(std::vector<TTPN> &programs)
{
    int i, num;

	TCSectionParser* pTableParser = t_Parser(TCPATParser::TABLE_ID);
	if (!pTableParser) {
		return false;
	}

    TCPATParser* pPATParser = static_cast<TCPATParser*>(pTableParser);
    if (!pPATParser->IsRecv())
    {
        printf("Pat IsRecv return false!!!\n");
        return false;
    }

    programs.clear();

    num = pPATParser->NumOfProgramList();
    for (i = 0; i < num; i++) {
        programs.push_back(pPATParser->ProgramNumber(i));
        printf("%d: program number %d\n", i, pPATParser->ProgramNumber(i));
    }

    return true;
}

bool CParserManager::GetPmtPidInfo(void)
{
    int i, num;
    short pid;

	printf("[%s] \n", __FUNCTION__);

	TCSectionParser* pTableParser = t_Parser(TCPATParser::TABLE_ID);
	if (pTableParser == NULL)
	{
		return false;
	}

    TCPATParser* pPATParser = static_cast<TCPATParser*>(pTableParser);
    if (false == pPATParser->IsRecv())
    {
        printf("Pat IsRecv return false!!!\n");
        return false;
    }

    m_PmtPids.clear();

    num = pPATParser->NumOfProgramList();
    for (i = 0; i < num; i++)
    {
        pid = pPATParser->ProgramPID(pPATParser->ProgramNumber(i));
        m_PmtPids.push_back(pid);
        printf("[%s] index %d, pmt pid 0x%02x\n", __FUNCTION__, i, pid);
    }

    return true;
}

bool CParserManager::IsPmtPid(short pid)
{
    auto iter = m_PmtPids.begin();;
    while (iter != m_PmtPids.end()) {
        if (*iter++ == pid) {
			printf("[%s] pid 0x%x, true\n", __FUNCTION__, pid);
			return true;
		}
	}

	printf("[%s] pid 0x%x, false\n", __FUNCTION__, pid);
	return false;
}

bool CParserManager::BeingFiltered(short pid)
{
    //return t_filterManager.FilterActive(pid);
    return false;
}

//void CParserManager::Init(void)
//{
//    //m_pTableParse = new CParserManager;
//    //m_pTableParse->Create("TableParse");
//}
//
//void CParserManager::Exit(void)
//{
//    //if (m_pTableParse != NULL)
//    //{
//    //    delete m_pTableParse;
//    //}
//}

//CParserManager* CParserManager::Instance(void)
//{
    //if (m_pTableParse == NULL)
    //{
    //    Init();
    //}

    //ASSERT(m_pTableParse != NULL);

    //return m_pTableParse;
//}

//void CParserManager::Start(void)
//{
//	PTEvent event;
//	event.type = CParserManager::EVENT_START_MANAGER;
//	event.receiver = (PCHandler *)this;
//	PCTask::Send(&event, false);
//}
//
//void CParserManager::Stop(void)
//{
//	PTEvent event;
//	event.type = CParserManager::EVENT_STOP_MANAGER;
//	event.receiver = (PCHandler *)this;
//	PCTask::Send(&event, true);
//}

//void CParserManager::t_Main(void)
//{
//    if (!t_Create())
//    {
//        return;
//    }
//
//
//    while (ExecuteEvent())
//    {
//        PCTime::Sleep(10);
//    }
//
//    t_Destroy();
//}
//

bool CParserManager::processSection(short pid, Section *pSection)
{
	printf("[processSection] pid 0x%04x ... \n", pid);
    if (!pSection->VerifyCrc32()) {
        printf("[CRC Error] section pid:0x%02x len:0x%04x tid:%02x tid_ext:%04x num %d/%d\n",
			pid, pSection->Length(), pSection->Data()[0], ((pSection->Data()[3] << 8) | pSection->Data()[4]),
			pSection->Data()[6], pSection->Data()[7]);
    } else {
	    if (t_Parse(pid, pSection))
	    {   // section appended
	        pSection = NULL;
	    }
    }

    if (pSection != NULL)
        delete pSection;

    return true;
}

bool CParserManager::t_AddParser(TCSectionParser* pParser)
{
	INT_ASSERT(pParser && pParser->Create());

	auto it = t_tableParserHash.find(pParser->TableId());
	if (it != t_tableParserHash.end()) {
		// parser exist
		return false;
	}

	t_tableParserHash[pParser->TableId()] = (void*)pParser;
	return true;
}

bool CParserManager::t_RemoveParser(unsigned char tableId)
{
	auto it = t_tableParserHash.find(tableId);
	if (it == t_tableParserHash.end()) {
		// parser not exist
		return false;
	}

	delete (TCSectionParser *)(it->second);
	t_tableParserHash.erase(it);
}

TCSectionParser* CParserManager::t_Parser(unsigned char tableId)
{
	auto it = t_tableParserHash.find(tableId);
	if (it == t_tableParserHash.end()) {
		printf("[%s] do not find matched parser for taibleid: 0x%02x\n", __FUNCTION__, tableId);
		return NULL;
	}

	return (TCSectionParser *)(it->second);
}


bool CParserManager::t_Parse(short pid, Section *pSection)
{
    unsigned char *pData = pSection->Data();
	TCSectionParser* pTableParser = t_Parser(SI_table_id(pData));
	if (pTableParser == NULL) {
		printf("No parser for tableid: 0x%02x\n", SI_table_id(pData));
		return false;
	}

	pTableParser->Parse(pid, pData);
    return pTableParser->SaveSection(pSection);
}

//bool CParserManager::t_Monitor(short PID, int tableId, int ms, unsigned char bVersion,bool bCheckCRC)
//{
//	TCSectionParser* pTableParser = t_Parser(tableId);
//	if (pTableParser != NULL)
//	{
//		//pTableParser->ResetTimer(ms);
//	}
//
//	return true;
//}
//
//bool CParserManager::t_StopMonitor(int tableId)
//{
//	TCSectionParser* pTableParser = t_Parser(tableId);
//	if (pTableParser != NULL)
//	{
//		//pTableParser->StopTimer();
//	}
//
//	return true;
//}

