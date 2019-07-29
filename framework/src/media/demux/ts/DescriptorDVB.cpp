
//#include "DTVmwConst.h"
#include "DTVmwType.h"
#include "DescriptorDVB.h"
//#include "DVBSGTParser.h"
//#include "DVBEITParser.h"
//#include "DVBSDTParser.h"
//#include "DVBNITParser.h"
//#include "DVBFSTParser.h"
//#include "DVBFNTParser.h"
//#include "DVBBATParser.h"
//#include "DVBTOTParser.h"
//#include "DVBTDTParser.h"
//#include "SITParser.h"
//#include "DVBRCTParser.h"
//#include "DVBLCNParser.h"
#include "PMTParser.h"
//#include "AITParser.h"
//#include "HashInt.h"
//#include "UNTParser.h"
#include "BaseDesc.h"
#include "DescConfDVB.h"
//#include "DescConfPsiDVB.h"
//#include "DescConfDS.h"
//#include "DescConfAstra.h"
//#include "DescContent.h"
//#include "DescLinkage.h"
//#include "DescPrivateDataSpecifier.h"
//#include "Tv.h"
//#include "Window.h"
//#include "TIMWBinder.h"

#define DVB_PDSD_INIT 0

#define PDSD_PRIVATE_DATA_SPECIFIER(BUFFER)     ((BUFFER[2]<<24) + (BUFFER[3]<<16) + (BUFFER[4]<<8) + BUFFER[5])
#define PRIVATE_DATA_INDICATOR_DESCRIPTOR_ID 15

/*!
\brief      Constructor
*/
TCDescriptorDVB::TCDescriptorDVB() : m_currPDS(DVB_PDSD_INIT)
{
}

/*!
\brief      Destructor
*/
TCDescriptorDVB::~TCDescriptorDVB()
{
}

TCDescConfBase*	TCDescriptorDVB::t_GetDescConf(unsigned char tableId)
{
	switch(tableId)
	{
        /* case TCDVBEITParser::TABLE_ID_ACTUAL_PF_PLUS_PLUS: */ ///<FSAT.
		//case TCDVBEITParser::TABLE_ID_ACTUAL_PF :
		//case TCDVBEITParser::TABLE_ID_OTHER_PF :
		//case TCDVBEITParser::TABLE_ID_ACTUAL_SCHED_1 :
		//case TCDVBEITParser::TABLE_ID_ACTUAL_SCHED_2 :
		//case TCDVBEITParser::TABLE_ID_OTHER_SCHED_1 :
		//case TCDVBEITParser::TABLE_ID_OTHER_SCHED_2 :
		//case TCDVBEITParser::TABLE_ID_ACTUAL_COMPRESSED_SCHED_1 :
		//case TCDVBEITParser::TABLE_ID_ACTUAL_COMPRESSED_SCHED_2 :
		//case TCDVBEITParser::TABLE_ID_OTHER_COMPRESSED_SCHED_1 :
		// Same with SGT
		//case TCDVBEITParser::TABLE_ID_OTHER_COMPRESSED_SCHED_2 :
		//case TCDVBSDTParser::TABLE_ID_ACTUAL :
		//case TCDVBSDTParser::TABLE_ID_OTHER :
		//case TCDVBNITParser::TABLE_ID_ACTUAL :
		//case TCDVBNITParser::TABLE_ID_OTHER :
		//case TCDVBFSTParser::TABLE_ID :
		//case TCDVBFNTParser::TABLE_ID :
		//case TCDVBBATParser::TABLE_ID :
		//case TCDVBTOTParser::TABLE_ID :
		//case TCDVBTDTParser::TABLE_ID :
		//case TCSITParser::TABLE_ID :
		//case TCUNTParser::TABLE_ID:
		//case TCDVBRCTParser::TABLE_ID:
		//case TCDVBLCNParser::TABLE_ID:
		//	return new TCDescConfDVB();

		//case TCDVBSGTParser::TABLE_ID:
		//	return new TCDescConfAstra;

		case TCPMTParser::TABLE_ID :
			//return new TCDescConfPsiDVB;
			return new TCDescConfDVB();

		//case TCAITParser::TABLE_ID :
		//	return new TCDescConfDS;

		default:
			break;
	}

	return NULL;
}

/*!
\brief      this function is called Before parsing. and this function initializes the element for parsing.
\remark	we must initialize current private data specifier before parsing.
\return    NONE
 */
void TCDescriptorDVB::t_InitParse(void)
{
    m_currPDS = DVB_PDSD_INIT;
}

/*!
\brief      Check whether the current descriptor could be added or not && Get private data specifier for current descriptor.
\param[in]  tag 	: the descriptor tag from descriptor raw data.
\param[in]  pData 	: descriptor raw data for parsing.
\param[out]  outPds 	:  Get private data specifier for current descriptor.
\return    	true		: current descriptor must be added in the current descriptor list. <br>
			false		: current descriptor must not be added in the current descriptor list. <br>
 */
bool TCDescriptorDVB::t_CheckAddingDesc(int tag,unsigned char* pData,unsigned long& outPds)
{
	//TIMWBinder* MWBinder = TIMWBinder::GetMWBinder();
	//INT_ASSERT(pData && MWBinder);

	// if the received descriptor is private data specifier descriptor, we don't add that descriptor in parser.
	/*if (tag == TCDescPrivateDataSpecifier::DESCRIPTOR_ID )
	{
		m_currPDS = PDSD_PRIVATE_DATA_SPECIFIER(pData);
		return false;
	}*/

#if 0
    if((tag == PRIVATE_DATA_INDICATOR_DESCRIPTOR_ID) && 0)
       (m_currPDS == DVB_PDSD_UK_FSAT))
    {
        // We don't process private data indicator descriptors, but in Freesat
        // the scope of the Freesat PDSD is terminated if one if encountered.
        // (See "Free Satellite Requirements for Interoperability,
        //  Part 3: System Management Version: Implementation 1.3, section 4.1.1
        //  for details).
        m_currPDS = DVB_PDSD_INIT;
    }


	if(tag >= PRIVATE_DESC_START_TAG && tag < PRIVATE_DESC_END_TAG)
	{
		// if the current privateDataSpecifier is invalid, we don't add the current descriptor in parser.
		//if(!MWBinder->CheckPDSD((TCWindow::EWindow)m_windowId,m_currPDS))
		{
			return false;
		}
	}
#endif

	outPds = m_currPDS;
	return true;
}

bool
TCDescriptorDVB::t_checkContentDescriptor(TCBaseDesc* desc, unsigned long curr_pds)
{
	if(desc->Tag() != 0x54)//TCDescContent::DESCRIPTOR_ID)
	{
		// It's not a TCDescContent descriptor, so let it be added.
		return true;
	}
#if 0
	TCDescContent *content = dynamic_cast<TCDescContent *>(desc);
	if(content == NULL)
	{
		return false;
	}

	//TIMWBinder* MWBinder = TIMWBinder::GetMWBinder();
	//INT_ASSERT(MWBinder);

	unsigned long matchedPDS = 0;
	//switch(MWBinder->GetDVBSpecCode((TCWindow::EWindow)m_windowId))
	{
		//case DVBSPEC_UK_FSAT :
		//	matchedPDS = DVB_PDSD_UK_FSAT;
		//	break;

		//case DVBSPEC_UK :
		//	matchedPDS = DVB_PDSD_UK_DTT;
		//	break;

		// if current country is not UK or UK_DTT , we do not concern of user defined type.
		//default :
			return true;
	}

	// Currently only Freesat/UK_DTT specifies a PDSD must be present if the descriptor
	// uses user defined types.

	if(curr_pds == matchedPDS)
	{
		content->SetPDSD(curr_pds);
	}
	/*
	for(int ii = 0; ii < content->NumOfContentLoop(); ++ii)
	{
		if(content->ContentNibbleLevel1(ii) == 0x0F)
		{
			if(curr_pds != matchedPDS)
			{
				// This is a user defined content nibble, and
				// so must be preceded by the Freesat PDSD or
				// ignored.
				return false;
			}
		}
	}
	*/
	return true;
#else
    return false;
#endif
}


bool TCDescriptorDVB::t_CheckLinkageDescriptor( TCBaseDesc* pDesc, unsigned long currPds )
{
	if( pDesc->Tag() != 0x4A)//TCDescLinkage::DESCRIPTOR_ID)
	{
		// It's not a linkage descriptor, so let it be added.
		return true;
	}

#if 0
	TCDescLinkage* pLinkage = dynamic_cast<TCDescLinkage*>(pDesc);
	if( pLinkage == NULL )
	{
		return false;
	}

	// Set current PDSD for UKDTG PVR --> for checking user_defined_id of extended event linkage.
	pLinkage->SetPDSD(currPds);

	if( pLinkage->LinkageType() < TCDescLinkage::LINKAGE_TYPE_USER_START
		|| pLinkage->LinkageType() > TCDescLinkage::LINKAGE_TYPE_USER_END )
	{
		// Linkage type is not private, so let the descriptor be added without further checks.
		return true;
	}

	// Check if private linkage type is compliant with current country spec.
	//TIMWBinder* MWBinder = TIMWBinder::GetMWBinder();
	//INT_ASSERT(MWBinder);

	bool addLinkage = true;
	//switch(MWBinder->GetDVBSpecCode((TCWindow::EWindow)m_windowId) )
	//{
		//case DVBSPEC_SKYD:
		//	if( currPds != DVB_PDSD_SKYD )
		//	{
		//		// Don't use linkage not preceeded with SkyD PDS.
		//		addLinkage = false;
		//	}
		//	break;

		//default :
			// By default any linkage type is allowed.
			//break;
	//}
	return addLinkage;
#else
    return false;
#endif
}

