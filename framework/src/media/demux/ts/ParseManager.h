
#ifndef __TABLE_PARSE_H__
#define __TABLE_PARSE_H__

#include <vector>
#include <map>

#include "DTVmwType.h"
#include "PATParser.h"
#include "PMTParser.h"
//#include "FilterManager.h"
//#include "HashInt.h"

#define MAX_PRIVATE_DATA_LEN (256)

class Section;
class TCSectionParser;
class CParserManager
{
private:
    //static CParserManager *m_pTableParse;  // singleton

    std::vector<short> m_PmtPids;

	//TCFilterManager t_filterManager;


protected:
	//! Table Parser HashTable
	TCHashInt t_tableParserHash;

	bool t_AddParser(TCSectionParser *pParser);
	bool t_RemoveParser(unsigned char tableId);
	TCSectionParser * t_Parser(unsigned char tableId);

public:
    CParserManager();
	virtual ~CParserManager();

	bool processSection(short pid, Section *pSection);
	bool t_Parse(short pid, Section *pSection);

	bool IsPatReceived(void);
	bool IsPmtReceived(TTPN progNum);
	bool IsPmtReceived(void);
	bool GetAudioPESPid(TTPN progNum, TTPID &pid);
    bool GetPrograms(std::vector<TTPN> &programs);
    bool GetPmtPidInfo(void);
    bool IsPmtPid(short pid);

	bool BeingFiltered(short pid);
	void AddFilter(short pid, int tableId, int ms, unsigned char bVersion, int priority, int response_time, bool bCheckCRC = true);
	bool RmvFilter(int tableId);
	bool RmvFilter(short pid, int tableId, unsigned char flag);

	//void Start(void);
	//void Stop(void);

    //void Init(void);
    //void Exit(void);
};




#endif

