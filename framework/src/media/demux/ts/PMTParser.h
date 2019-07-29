#ifndef __PMT_PARSER_H__
#define __PMT_PARSER_H__

#include <map>
#include "DTVmwType.h"
#include "SectionParser.h"

class Section;
class TCPMTInstance;
class TCPMTParser : public TCSectionParser
{
public:
	enum {
		TABLE_ID = 0x02,
	};

private:
	TTPN m_programNumber;

	std::map<int, int> m_PMTElements;	// Key = (pid<<16 | prog_num), data = pid

protected:

	std::map<TTPN, TCPMTInstance *> t_pmtInstanceHash;

	virtual bool t_Parse(unsigned char* pData, int size);

	virtual bool t_Create(void);

	virtual void t_Initialize(void);


public:

	TCPMTParser();

	virtual ~TCPMTParser();

	int      NumOfPMTInstance(void);

	TTPN      ProgramNumber(void);

	TCPMTInstance*  PMTInstance(TTPN programNumber);

	TCPMTInstance*  PMTInstanceOfIndex(unsigned int index);

	void UpdatePMTElements(std::map<int, int>& pmtMap);

	void ClearPMTElements(void);

	bool SaveSection(Section* pSection);
    bool ListSection(std::vector<Section*>& sectionList);

	static int PMTKey(int Pid, int ProgNum);
};

#endif /* __PMT_PARSER_H__ */
