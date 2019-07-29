#ifndef __SECTION_H__
#define __SECTION_H__

#include <stdint.h>
#include "DTVmwType.h"


class Section
{
public:
	Section();
    Section(uint16_t u16Pid, uint8_t continuityCounter, uint8_t *pu8Data, uint16_t u16Size); // TODEL
    virtual ~Section();

    std::shared_ptr<Section> create(uint16_t u16Pid, uint8_t continuityCounter, uint8_t *pu8Data, uint16_t u16Size);
	bool init(uint16_t u16Pid, uint8_t continuityCounter, uint8_t *pu8Data, uint16_t u16Size);

    bool AppendData(uint16_t u16Pid, uint8_t continuityCounter, uint8_t *pu8Data, uint16_t u16Size);
    bool VerifyCrc32(void);
    bool IsSectionCompleted(void);
    uint8_t* Data(void);
    uint16_t Length(void);

private:

    uint16_t m_section_length; // not section_length field data, but total length
    uint16_t m_offset;
    uint16_t m_pid;
    uint8_t *m_data;
    uint8_t  m_continuity_counter;
};

#endif /* __SECTION_H__ */
