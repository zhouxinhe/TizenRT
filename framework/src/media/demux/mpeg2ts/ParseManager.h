
#ifndef __PARSE_MANAGER_H__
#define __PARSE_MANAGER_H__

#include <map>
#include <vector>

#include "Mpeg2TsTypes.h"

class Section;
class SectionParser;
class ParserManager
{
public:
    ParserManager();
	virtual ~ParserManager();

	bool processSection(ts_pid_t pid, Section *pSection);
	bool IsPatReceived(void);
	bool IsPmtReceived(prog_num_t progNum);
	bool IsPmtReceived(void);
	bool GetAudioStreamInfo(prog_num_t progNum, uint8_t &streamType, ts_pid_t &pid);
    bool GetPrograms(std::vector<prog_num_t> &programs);
    bool GetPmtPidInfo(void);
    bool IsPmtPid(ts_pid_t pid);

protected:
	bool t_AddParser(SectionParser *pParser);
	bool t_RemoveParser(table_id_t tableId);
	SectionParser *t_Parser(table_id_t tableId);
	bool t_Parse(ts_pid_t pid, Section *pSection);

private:
	std::map<table_id_t, SectionParser *> t_tableParserMap;
	std::vector<ts_pid_t> m_PmtPids;
};

#endif
