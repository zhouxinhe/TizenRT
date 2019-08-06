#include <assert.h>
#include <debug.h>

#include "Mpeg2TsTypes.h"
#include "Section.h"
#include "SectionParser.h"
#include "PATParser.h"
#include "PMTParser.h"
#include "PMTInstance.h"
#include "PMTElementary.h"
#include "TSParser.h"
#include "ParseManager.h"

#define TABILE_ID(buffer) 	((buffer)[0])

ParserManager::ParserManager()
{
	// Add PAT parser
	t_AddParser(new PATParser());
    // Add PMT parser
	t_AddParser(new PMTParser());
}

ParserManager::~ParserManager()
{
	// TODO: delete items in map
	t_tableParserMap.clear();
}

bool ParserManager::IsPatReceived(void)
{
	SectionParser *pTableParser = t_Parser(PATParser::TABLE_ID);
	if (pTableParser == NULL) {
		printf("[%s] no PAT parser\n", __FUNCTION__);
		return false;
	}

	PATParser *pPATParser = static_cast<PATParser*>(pTableParser);
	printf("[%s] return %d\n", __FUNCTION__, pPATParser->IsRecv());
	return pPATParser->IsRecv();
}

bool ParserManager::IsPmtReceived(prog_num_t progNum)
{
	SectionParser *pTableParser = t_Parser(PMTParser::TABLE_ID);
	if (pTableParser == NULL) {
		return false;
	}

	PMTParser *pPMTParser = static_cast<PMTParser*>(pTableParser);
	PMTInstance *pPMTInstance = pPMTParser->GetPMTInstance(progNum);
	if (pPMTInstance == NULL) {
		return false;
	}

	return pPMTInstance->IsValid();
}

bool ParserManager::IsPmtReceived(void)
{
	PATParser *pPATParser = static_cast<PATParser*>(t_Parser(PATParser::TABLE_ID));

	if (pPATParser && pPATParser->IsRecv()) {
		size_t i;
		size_t progs = pPATParser->NumOfProgramList();
		for (i = 0; i < progs; i++) {
			if (!IsPmtReceived(pPATParser->ProgramNumber(i))) {
				return false;
			}
		}

		return true;
	}

	return false;
}

bool ParserManager::GetAudioStreamInfo(prog_num_t progNum, uint8_t &streamType, ts_pid_t &pid)
{
	PMTParser *pPMTParser = static_cast<PMTParser*>(t_Parser(PMTParser::TABLE_ID));
	PMTInstance *pPMTInstance = pPMTParser->GetPMTInstance(progNum);

	if (pPMTInstance && pPMTInstance->IsValid()) {
		size_t i;
		size_t num = pPMTInstance->NumOfElementary();
		for (i = 0; i < num; i++) {
			PMTElementary *pStream = pPMTInstance->GetPMTElementary(i);
			assert(pStream);
			switch (pStream->StreamType()) {
				case PMTElementary::STREAM_TYPE_AUDIO_AAC:
				case PMTElementary::STREAM_TYPE_AUDIO_MPEG2:
				case PMTElementary::STREAM_TYPE_AUDIO_AC3:
				case PMTElementary::STREAM_TYPE_AUDIO_MPEG1:
				case PMTElementary::STREAM_TYPE_AUDIO_HE_AAC:
					streamType = pStream->StreamType();
					pid = pStream->ElementaryPID();
					printf("[%s] stream type 0x%02x, pid 0x%x\n", __FUNCTION__, streamType, pid);
					return true;
			}
		}
	}

	return false;
}

bool ParserManager::GetPrograms(std::vector<prog_num_t> &programs)
{
    size_t i, num;

	SectionParser *pTableParser = t_Parser(PATParser::TABLE_ID);
	if (!pTableParser) {
		return false;
	}

    PATParser *pPATParser = static_cast<PATParser*>(pTableParser);
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

bool ParserManager::GetPmtPidInfo(void)
{
    size_t i, num;
    ts_pid_t pid;
	prog_num_t progNum;
	std::map<int, ts_pid_t> pmt_elements;

	printf("[%s] \n", __FUNCTION__);

	SectionParser *pTableParser = t_Parser(PATParser::TABLE_ID);
	if (pTableParser == NULL) {
		return false;
	}

    PATParser *pPATParser = static_cast<PATParser*>(t_Parser(PATParser::TABLE_ID));
	assert(pPATParser);
    if (!pPATParser->IsRecv()) {
        printf("Pat IsRecv return false!!!\n");
        return false;
    }

    m_PmtPids.clear();

	num = pPATParser->NumOfProgramList();
	for (i = 0; i < num; ++i) {
		progNum = pPATParser->ProgramNumber(i);
		pid = pPATParser->ProgramPID(progNum);
		if ((pid != (ts_pid_t)INVALID_PID) && (progNum != (prog_num_t)PATParser::NETWORK_PID)) {
			int key = PMTParser::makeKey(pid, progNum);
			pmt_elements[key] = pid;
			m_PmtPids.push_back(pid);
			printf("[%s] index %d, pmt pid 0x%02x\n", __FUNCTION__, i, pid);
		}
	}

	PMTParser *pPMTParser = static_cast<PMTParser *>(t_Parser(PMTParser::TABLE_ID));
	assert(pPMTParser);
	pPMTParser->Initialize();
	pPMTParser->UpdatePMTElements(pmt_elements);
    return true;
}

bool ParserManager::IsPmtPid(ts_pid_t pid)
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

bool ParserManager::processSection(ts_pid_t pid, Section *pSection)
{
	medvdbg("[processSection] pid 0x%04x ... \n", pid);
    if (!pSection->VerifyCrc32()) {
        meddbg("section crc32 verify failed!\n");
		return false;
    }

	return t_Parse(pid, pSection);
}

bool ParserManager::t_AddParser(SectionParser *pParser)
{
	auto it = t_tableParserMap.find(pParser->TableId());
	if (it != t_tableParserMap.end()) {
		// parser exist
		return false;
	}

	t_tableParserMap[pParser->TableId()] = pParser;
	return true;
}

bool ParserManager::t_RemoveParser(table_id_t tableId)
{
	auto it = t_tableParserMap.find(tableId);
	if (it == t_tableParserMap.end()) {
		return false;
	}

	delete it->second;
	t_tableParserMap.erase(it);
	return true;
}

SectionParser *ParserManager::t_Parser(table_id_t tableId)
{
	auto it = t_tableParserMap.find(tableId);
	if (it == t_tableParserMap.end()) {
		printf("[%s] do not find matched parser for taibleid: 0x%02x\n", __FUNCTION__, tableId);
		return nullptr;
	}

	return (SectionParser *)(it->second);
}

bool ParserManager::t_Parse(ts_pid_t pid, Section *pSection)
{
	bool result = false;
	uint8_t *pData = pSection->Data();
	table_id_t tableId = TABILE_ID(pData);
	SectionParser *pTableParser = t_Parser(tableId);
	if (!pTableParser) {
		printf("table parser is null!\n");
		return false;
	}

	result = pTableParser->Parse(pid, pData);
	if (result) {
		switch (tableId) {
		case PATParser::TABLE_ID: // PAT received
			GetPmtPidInfo();
			break;
		default:
			break;
		}
	}

	return result;
}
