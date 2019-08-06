#ifndef __PAT_PARSER_H__
#define __PAT_PARSER_H__

#include <map>
#include "Mpeg2TsTypes.h"
#include "SectionParser.h"
#include "BaseSection.h"


class PATParser : public SectionParser, public BaseSection
{
public:
	enum {
		TABLE_ID = 0x00,
		NETWORK_PID = 0x00,
	};

	PATParser();

	virtual ~PATParser();

	virtual void DeleteAll(void);

	size_t NumOfProgramList(void);

	prog_num_t ProgramNumber(uint32_t index);

	ts_pid_t ProgramPID(prog_num_t programNumber);

	stream_id_t TansportStreamId(void);

	ts_pid_t NetworkPID(void);

	bool IsRecv(void);

protected:
	virtual bool t_Create(void);

	virtual void t_Initialize(void);

	virtual bool t_Parse(uint8_t *pData, uint32_t size);

	void t_AddProgram(prog_num_t programNumber, ts_pid_t programPID);

private:
	std::map<prog_num_t, ts_pid_t> m_programMap;

	stream_id_t m_transportStreamId;

	ts_pid_t m_networkPID;
};

#endif /* __PAT_PARSER_H__ */

