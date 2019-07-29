#include "DTVmwType.h"
#include "PESPacket.h"
#include "PESParser.h"


PESParser::PESParser()
{
	t_pPESData  = NULL;
	t_packetLength = 0;
	t_pid = -1;
}

PESParser::~PESParser()
{
}

bool PESParser::Create(void)
{
}

void PESParser::Initialize(void)
{

	return;
}

/*!
\brief      Section Data�� Parsing �Ѵ�.
\param[in]  pid(short)		Packet Identifier
\param[in]  pData(char*)	Section Data�� �ּ�
			- TCWindow::WINDOW_MAIN
			- TCWindow::WINDOW_VIRTUAL1
\return     None
\remarks
\par        Example:
\code
			TCPATParser patParser;
			patParser.Create();
			bool ret = patParser.Parse(0x00, pSectionData, TCWindow::WINDOW_MAIN);
			if(ret)
			{
				//�������� SectionData�� ���� ���������� Parsing �� ���..
			}



\endcode
\see
*/
bool PESParser::Parse(short pid, unsigned char* pData)
{
	t_pid                    = pid;
	t_pPESData               = pData;
	t_packetLength           = (pData[4] << 8) | pData[5];//SI_section_length(pData);

	return t_Parse(&pData[6], t_packetLength);
}


bool PESParser::t_Parse(unsigned char* pData, int size)
{
	//TODO：：
	return true;
}


//PESParser& PESParser::operator=(const PESParser& parser)
//{
//	t_pPESData = parser.t_pPESData;
//	t_pid = parser.t_pid;
//	t_packetLength = parser.t_packetLength;
//	return *this;
//}

