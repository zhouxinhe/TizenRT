#ifndef __SECTION_PARSER_H__
#define __SECTION_PARSER_H__

#include <vector>


#define SI_table_id(BUFFER)                       (BUFFER[0])
#define SI_section_syntax_indicator(BUFFER)       ((BUFFER[1]>>7)&1)
#define SI_private_indicator(BUFFER)              ((BUFFER[1]>>6)&1)
#define SI_section_length(BUFFER)                 (((BUFFER[1]&0x0F)<<8)+(BUFFER[2]))

class Section;
class TCSectionParser
{
public:
	enum {
		PAT_PID = 0x0000,
	};

	enum
	{
		SECTION_HEADER_LENGTH = 3,
		PSIP_HEADER_LENGTH    = 6,
		LONG_FORM_HEADER_LENGTH = 5,
		SECTION_MAX_LENGTH    = 4096,
	};

protected:
	//! Pointer to the task this parser runs in.
	//PCTask*          m_pTask;
	//!
	//int              m_interval;
	//bool             m_bTimeOut;

	bool             m_bRecv;

protected:

	//! Constructor.
    //! @param [in] tableId the table ID of the table being parsed by this
    //!                     section parser.
    //! @param [in] pTask a pointer to the PCTask this parser runs in.
	TCSectionParser(int tableId, void* pTask);

	unsigned char* t_pSectionData;

	//! section_pid
	short t_pid;
	//! table_Id
	unsigned char  t_tableId;
	//! section_syntax_indicatior
	bool  t_sectionSyntaxIndicator;
	//! private_indicatior
	bool  t_privateIndicator;
	//! section_length
	short t_sectionLength;

	// SI HEADER

	//! table_id_extention
	unsigned short  t_tableIdExtension; // transport stream id / program number
	//! version_number
	char           t_versionNumber;
	//! current_next_indicator
	bool           t_currentNextIndicator;
	//! section_number
	unsigned char  t_sectionNumber;
	//! last_section_number
	unsigned char  t_lastSectionNumber;
	//! protocal_version
	unsigned char  t_protocolVersion;
	//! crc32
	unsigned long t_crc;

	//!
	//virtual PCTask*      t_PCTask(void) { return m_pTask;}

	/// Implemented in the derived class to process the section data.
    /// \param [in] pData a pointer to the section data.
    /// \param [in] size the length of the section data.
	virtual bool t_Parse(unsigned char* pData, int size) = 0;

	//virtual bool         t_OnAlarm(const PTEvent *evnt);

	virtual bool t_Create(void)     { return true; }

	virtual void t_Initialize(void)=0;

public:
	//!
	virtual ~TCSectionParser();

	virtual bool Create(void);
	//!
	virtual void Initialize(void);
	//!
	virtual bool  Parse(short PID, unsigned char* pData);

	virtual bool t_CheckPSIPTable(unsigned char tableId);

	//virtual bool  IsTimeOut(void) { return m_bTimeOut; }

	virtual bool  IsRecv(void)    { return m_bRecv; }

	//virtual bool  ResetTimer(int interval = 0);

	//virtual bool  StopTimer(void);

	virtual short  Pid(void)  { return t_pid; }

    virtual unsigned char  TableId(void)   { return t_tableId; }

    /// Returns the table ID extension value.
    virtual unsigned short TableIdExt(void)    { return t_tableIdExtension; }

	virtual unsigned char  SectionSyntaxIndicator(void) { return t_sectionSyntaxIndicator;}

	virtual unsigned char  PrivateIndicator(void)       { return t_privateIndicator;}

	virtual short          SectionLength(void)          { return t_sectionLength;}

	virtual char           VersionNumber(void)          { return t_versionNumber;}

	virtual char           CurrentNextIndicator(void)   { return t_currentNextIndicator;}

	virtual unsigned char  SectionNumber(void)          { return t_sectionNumber;}

	virtual unsigned char  LastSectionNumber(void)      { return t_lastSectionNumber;}

	virtual unsigned long SectionCRC(void)				{ return t_crc;}

	virtual TCSectionParser& operator=(const TCSectionParser& parser);

    virtual bool SaveSection(Section* pSection) { return false; }

    virtual bool ListSection(std::vector<Section *>& sectionList) { return false; }
};




#endif /* __SECTION_PARSER_H__ */
