#ifndef __PES_PARSER_H__
#define __PES_PARSER_H__

#define PES_PACKET_START_CODE_PREFIX 0x000001

class PESParser
{
public:

	PESParser();
	virtual ~PESParser();

	bool Create(void);
	void Initialize(void);

	bool  Parse(short PID, unsigned char* pData);
	short Pid(void)  { return t_pid; }

	//virtual PESParser& operator=(const PESParser& parser);
private:
	unsigned char *t_pPESData;
	short t_packetLength;
	short t_pid;

	/// Implemented in the derived class to process the section data.
    /// \param [in] pData a pointer to the section data.
    /// \param [in] size the length of the section data.
	bool t_Parse(unsigned char* pData, int size);
};

#endif /* __PES_PARSER_H__ */
