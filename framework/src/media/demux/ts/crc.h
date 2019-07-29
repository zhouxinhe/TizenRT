
#ifndef _CRC_H_
#define _CRC_H_


class CRC
{
public:
    CRC() {}

    static unsigned int CRC_MPEG32(void *, unsigned int );
private:
    /* lookup tables */
    static const unsigned int ulTable_MPEG32[256];
};

#endif   /* _CRC_H */
