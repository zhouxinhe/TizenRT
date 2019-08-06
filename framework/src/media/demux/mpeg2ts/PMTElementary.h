#ifndef __PMT_ELEMENTARY_H__
#define __PMT_ELEMENTARY_H__

#include "Mpeg2TsTypes.h"

class PMTElementary
{
public:
	enum {
		STREAM_TYPE_AUDIO_MPEG1  = 0x03,
		STREAM_TYPE_AUDIO_MPEG2  = 0x04,
		STREAM_TYPE_AUDIO_AAC    = 0x0F,
		STREAM_TYPE_AUDIO_HE_AAC = 0x11,
		STREAM_TYPE_AUDIO_AC3    = 0x81,
	};

	PMTElementary();
	~PMTElementary();

	uint8_t StreamType(void);
	ts_pid_t ElementaryPID(void);
	int16_t ESInfoLength(void);
	int32_t Parse(uint8_t *pData);

private:
	// stream type
	uint8_t m_streamType;
	// elementary PID
	ts_pid_t m_elementary_PID;
	// ES info length
	int16_t m_esInfoLength;
};

#endif /* __PMT_ELEMENTARY_H__ */
