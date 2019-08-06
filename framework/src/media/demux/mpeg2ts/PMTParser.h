#ifndef __PMT_PARSER_H__
#define __PMT_PARSER_H__

#include <map>
#include "Mpeg2TsTypes.h"
#include "SectionParser.h"

class Section;
class PMTInstance;
class PMTParser : public SectionParser
{
public:
	enum {
		TABLE_ID = 0x02,
	};

	PMTParser();
	virtual ~PMTParser();

	size_t NumOfPMTInstance(void);

	prog_num_t ProgramNumber(void);

	PMTInstance *GetPMTInstance(prog_num_t programNumber);

	PMTInstance *PMTInstanceOfIndex(uint32_t index);

	void UpdatePMTElements(std::map<int, ts_pid_t> &pmtMap);

	void ClearPMTElements(void);

	static int makeKey(ts_pid_t pid, prog_num_t progNum);

protected:
	virtual bool t_Parse(uint8_t *pData, uint32_t size);

	virtual bool t_Create(void);

	virtual void t_Initialize(void);

private:
	prog_num_t m_programNumber;
	std::map<int, ts_pid_t> m_PMTElements;	// <key = (pid<<16 | prog_num), data = pid>
	std::map<prog_num_t, PMTInstance *> m_PmtInstances;
};

#endif /* __PMT_PARSER_H__ */
