/******************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include <debug.h>
#include "Mpeg2TsTypes.h"
#include "Section.h"
#include "SectionParser.h"
#include "PATParser.h"
#include "PMTParser.h"
#include "PMTInstance.h"
#include "PMTElementary.h"
#include "ParseManager.h"

#define TABILE_ID(buffer)   ((buffer)[0])

ParserManager::ParserManager()
{
	// Add PAT parser
	addParser(new PATParser());
	// Add PMT parser
	addParser(new PMTParser());
}

ParserManager::~ParserManager()
{
	// TODO: delete items in map
	t_tableParserMap.clear();
}

bool ParserManager::isPATReceived(void)
{
	SectionParser *pTableParser = getParser(PATParser::TABLE_ID);
	if (pTableParser == nullptr) {
		meddbg("no PAT parser\n");
		return false;
	}

	PATParser *pPATParser = static_cast<PATParser*>(pTableParser);
	return pPATParser->isRecv();
}

bool ParserManager::isPMTReceived(prog_num_t progNum)
{
	SectionParser *pTableParser = getParser(PMTParser::TABLE_ID);
	if (pTableParser == nullptr) {
		return false;
	}

	PMTParser *pPMTParser = static_cast<PMTParser*>(pTableParser);
	auto pPMTInstance = pPMTParser->getPMTInstance(progNum);
	if (pPMTInstance == nullptr) {
		return false;
	}

	return pPMTInstance->isCompleted();
}

bool ParserManager::isPMTReceived(void)
{
	PATParser *pPATParser = static_cast<PATParser*>(getParser(PATParser::TABLE_ID));

	if (pPATParser && pPATParser->isRecv()) {
		size_t i;
		size_t progs = pPATParser->sizeOfProgram();
		for (i = 0; i < progs; i++) {
			if (!isPMTReceived(pPATParser->getProgramNumber(i))) {
				return false;
			}
		}

		return true;
	}

	return false;
}

bool ParserManager::getAudioStreamInfo(prog_num_t progNum, uint8_t &streamType, ts_pid_t &pid)
{
	PMTParser *pPMTParser = static_cast<PMTParser*>(getParser(PMTParser::TABLE_ID));
	auto pPMTInstance = pPMTParser->getPMTInstance(progNum);

	if (pPMTInstance && pPMTInstance->isCompleted()) {
		size_t i;
		size_t num = pPMTInstance->numOfElementary();
		for (i = 0; i < num; i++) {
			auto pStream = pPMTInstance->getPMTElementary(i);
			if (!pStream) {
				meddbg("Run out of memory!\n");
				return false;
			}

			switch (pStream->getStreamType()) {
				case PMTElementary::STREAM_TYPE_AUDIO_AAC:   // fall through
				case PMTElementary::STREAM_TYPE_AUDIO_MPEG2: // fall through
				case PMTElementary::STREAM_TYPE_AUDIO_AC3:   // fall through
				case PMTElementary::STREAM_TYPE_AUDIO_MPEG1: // fall through
				case PMTElementary::STREAM_TYPE_AUDIO_HE_AAC:
					streamType = pStream->getStreamType();
					pid = pStream->getElementaryPID();
					medvdbg("stream type 0x%02x, pid 0x%x\n", streamType, pid);
					return true;
				default:
					break;
			}
		}
	}

	meddbg("PMT of program number %d has not be received!\n", progNum);
	return false;
}

bool ParserManager::getPrograms(std::vector<prog_num_t> &programs)
{
	size_t i, num;

	PATParser *pPATParser = static_cast<PATParser *>(getParser(PATParser::TABLE_ID));
	if (!pPATParser) {
		meddbg("PAT parser is not found!\n");
		return false;
	}

	if (!pPATParser->isRecv()) {
		meddbg("PAT has not been received yet!\n");
		return false;
	}

	num = pPATParser->sizeOfProgram();
	for (i = 0; i < num; i++) {
		programs.push_back(pPATParser->getProgramNumber(i));
	}

	return true;
}

bool ParserManager::syncProgramInfoFromPAT(void)
{
	size_t i, num;
	ts_pid_t pid;
	prog_num_t progNum;
	std::map<int, ts_pid_t> pmt_elements;

	PATParser *pPATParser = static_cast<PATParser*>(getParser(PATParser::TABLE_ID));
	if (!pPATParser) {
		meddbg("PAT parser is not found!\n");
		return false;
	}

	if (!pPATParser->isRecv()) {
		meddbg("PAT has not been received yet!\n");
		return false;
	}

	// Clear current PMT Pids
	mPMTPids.clear();

	// Update new informations from PAT
	num = pPATParser->sizeOfProgram();
	for (i = 0; i < num; ++i) {
		progNum = pPATParser->getProgramNumber(i);
		pid = pPATParser->getProgramMapPID(progNum);
		if ((pid != (ts_pid_t)INVALID_PID) && (progNum != (prog_num_t)PATParser::NETWORK_PID_PN)) {
			int key = PMTParser::makeKey(pid, progNum);
			pmt_elements[key] = pid;
			mPMTPids.push_back(pid);
			medvdbg("index %d, pmt pid 0x%02x\n", i, pid);
		}
	}

	PMTParser *pPMTParser = static_cast<PMTParser *>(getParser(PMTParser::TABLE_ID));
	if (!pPMTParser) {
		meddbg("PMT parser is not found!\n");
		return false;
	}
	// Reinitialize PMT parser and update new PMT elements to PMT parser
	pPMTParser->Initialize();
	pPMTParser->updatePMTElements(pmt_elements);
	return true;
}

bool ParserManager::isPMTPid(ts_pid_t pid)
{
	auto iter = mPMTPids.begin();;
	while (iter != mPMTPids.end()) {
		if (*iter++ == pid) {
			return true;
		}
	}

	return false;
}

bool ParserManager::processSection(std::shared_ptr<Section> pSection)
{
	if (pSection == nullptr) {
		meddbg("section is nullptr!\n");
		return false;
	}

	if (!pSection->verifyCrc32()) {
		meddbg("section invalid!\n");
		return false;
	}

	uint8_t *pData = pSection->getDataPtr();
	table_id_t tableId = TABILE_ID(pData);
	auto pTableParser = getParser(tableId);
	if (pTableParser == nullptr) {
		meddbg("table parser is nullptr!\n");
		return false;
	}

	bool result = pTableParser->parse(pSection->getPid(), pData);
	if (result) {
		switch (tableId) {
		case PATParser::TABLE_ID: // PAT received
			if (!syncProgramInfoFromPAT()) {
				meddbg("Sync program info failed when PAT received!\n");
				//
			}
			break;
		default:
			break;
		}
	}

	return result;

}

bool ParserManager::addParser(SectionParser *pParser)
{
	auto it = t_tableParserMap.find(pParser->getTableId());
	if (it != t_tableParserMap.end()) {
		// parser exist
		return false;
	}

	t_tableParserMap[pParser->getTableId()] = pParser;
	return true;
}

bool ParserManager::removeParser(table_id_t tableId)
{
	auto it = t_tableParserMap.find(tableId);
	if (it == t_tableParserMap.end()) {
		return false;
	}

	delete it->second;
	t_tableParserMap.erase(it);
	return true;
}

SectionParser *ParserManager::getParser(table_id_t tableId)
{
	auto it = t_tableParserMap.find(tableId);
	if (it == t_tableParserMap.end()) {
		meddbg("No parser for taibleid: 0x%02x\n", tableId);
		return nullptr;
	}

	return (SectionParser *)(it->second);
}
