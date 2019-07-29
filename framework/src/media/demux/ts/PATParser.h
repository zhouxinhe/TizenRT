#ifndef __PAT_PARSER_H__
#define __PAT_PARSER_H__

#include <map>
#include "SectionParser.h"
#include "BaseSection.h"
//#include "SortedList.h"
#include "DTVmwType.h"

////! TTProgramList structure
//struct TTProgramList
//{
//	//! program_number
//	TTPN programNumber;
//	//! program_PID
//	TTPID programPID;
//};




class TCPATParser : public TCSectionParser, public TCBaseSection
{
public:
	enum
	{
		TABLE_ID    = 0x00,
		NETWORK_PID = 0x00,
	};

private:
	std::map<TTPN, TTPID> m_programMap;
	TTTSID m_transportStreamId;
	TTPID m_networkPID;

protected:
	virtual bool t_Create(void);
	virtual void t_Initialize(void);
	virtual bool t_Parse(unsigned char* pData, int size);
	void t_AddProgram(TTPN programNumber, TTPID programPID);


public:

	TCPATParser();
	virtual ~TCPATParser();

	virtual void DeleteAll(void);

	int NumOfProgramList(void);
	TTPN ProgramNumber(int index);
	TTPID 	ProgramPID(TTPN programNumber);
	TTTSID   TansportStreamId(void);
	TTPID 	NetworkPID(void);
	bool  IsRecv(void);

    bool SaveSection(Section* pSection);
    bool ListSection(std::vector<Section*>& sectionList);
};

#endif /* __PAT_PARSER_H__ */

