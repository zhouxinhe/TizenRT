//#include <vector>
//#include "Channel.h"
//#include "Tv.h"
//#include "Window.h"
//#include "TIMWBinder.h"
//#include "OSAbstraction.h"
#include "DTVmwType.h"
#include "DescConfDVB.h"
//#include "DescriptorDVB.h"
#include "DescDefault.h"
#include "DescMetadataPointer.h"

#if 0
#include "DescExtendedEvent.h"
#include "DescConditionalAccess.h"
#include "DescContent.h"
#include "DescShortEvent.h"
#include "DescPrivateDataSpecifier.h"
#include "DescAC3.h"
#include "DescEnhancedAC3.h"
#include "DescService.h"
#include "DescLocalTimeOffset.h"
#include "DescNetworkName.h"
#include "DescBouquetName.h"
//#include "DescLinkage.h"
#endif
#if 0
#include "DescParentalRating.h"
#include "DescMultilingualNetworkName.h"
#include "DescMultilingualServiceName.h"
#include "DescTerrestrialDeliverySystem.h"
#include "DescCableDeliverySystem.h"
#include "DescServiceAvailability.h"
#include "DescFrequencyList.h"
#include "DescScheduling.h"
#include "DescComponent.h"
#include "DescCRID.h"
#include "DescDefaultAuthority.h"
#include "DescServiceList.h"
#include "DescDataBroadcastId.h"
#include "DescSSULocation.h"
#include "DescSatelliteDeliverySystem.h"
#include "DescFSatLogicalChannel.h"
#include "DescFSatTunnelledData.h"
#include "DescFSatAltTunnelledData.h"
#include "DescFSatLinkage.h"
#include "DescFSatRegionName.h"
#include "DescFSatServiceGroup.h"
#include "DescFSatInteractiveStorage.h"
#include "DescFSatInfoLocation.h"
#include "DescFSatServiceGroupName.h"
#include "DescFSatShortServiceName.h"
#include "DescFSatGuidance.h"
#include "DescFSatInteractiveRestriction.h"
#include "DescFSatContentManagement.h"
#include "DescFTAContentManagement.h"
#include "DescCountryAvailability.h"
#include "DescGuidance.h"
#include "DescUKDTTServiceAttribute.h"
#include "DescNetworkChangeNotify.h"
#include "DescLogicalChannelV2.h"
#include "DescAstraBouquetList.h"
#include "DescAstraServiceListName.h"
#include "DescAstraVirtualServiceId.h"
#include "DescCAIdentifier.h"
#include "DescCanalPlusServicePlanSelection.h"
#include "DescCanalPlusRegionalisationPool.h"
#include "CountrySpecEnum.h"
//#include "CountryManagerSingleton.h"
#include "DescServiceIdentifier.h"
#include "DescSogecablePrivateChannelList.h"
#include "DescDigiturkAlternativeFrequency.h"
#include "DescDigiturkLogicalChannel.h"
#include "DescDigiturkServiceTheme.h"
#include "DescDSmartSatelliteDeliverySystem.h"
#include "DescCIPlusService.h"
#include "DescEutelsatChannelNumber.h"
#include "DescMetadataPointer.h"
#include "DescCIPlusContentLabel.h"
#include "DescDataBroadcast.h"
//#include "DescExtension.h"
//#include "DescRelocatedTS.h"
#endif



TCDescConfDVB::TCDescConfDVB(void)
{
}

TCBaseDesc*
TCDescConfDVB::NewDescriptor(int tag, const unsigned char *pData,
							 unsigned long pds)
{
	switch (tag)
	{
#if 0
    case TCDescShortEvent::DESCRIPTOR_ID:
        return new TCDescShortEvent;
	case TCDescExtendedEvent::DESCRIPTOR_ID:
		return new TCDescExtendedEvent;

	case TCDescContent::DESCRIPTOR_ID:
		return new TCDescContent;

	case TCDescPrivateDataSpecifier::DESCRIPTOR_ID:
		return new TCDescPrivateDataSpecifier;

	case TCDescAC3::DESCRIPTOR_ID:
		return new TCDescAC3;

	case TCDescEnhancedAC3::DESCRIPTOR_ID:
		return new TCDescEnhancedAC3;

	case TCDescService::DESCRIPTOR_ID:
		return new TCDescService;

	case TCDescLocalTimeOffset::DESCRIPTOR_ID:
		return new TCDescLocalTimeOffset;

	case TCDescNetworkName::DESCRIPTOR_ID:
		return new TCDescNetworkName;

	case TCDescBouquetName::DESCRIPTOR_ID:
		return new TCDescBouquetName;
	case TCDescLinkage::DESCRIPTOR_ID:
		return new TCDescLinkage;
	case TCDescParentalRating::DESCRIPTOR_ID:
		return new TCDescParentalRating;

	case TCDescMultilingualNetworkName::DESCRIPTOR_ID:
		return new TCDescMultilingualNetworkName;

	case TCDescMultilingualServiceName::DESCRIPTOR_ID:
		return new TCDescMultilingualServiceName;

	case TCDescTerrestrialDeliverySystem::DESCRIPTOR_ID:
		return new TCDescTerrestrialDeliverySystem;

	case TCDescCableDeliverySystem::DESCRIPTOR_ID:
		return new TCDescCableDeliverySystem;

	case TCDescServiceAvailability::DESCRIPTOR_ID:
		return new TCDescServiceAvailability;

	case TCDescCountryAvailability::DESCRIPTOR_ID:
		return new TCDescCountryAvailability;

	case TCDescFrequencyList::DESCRIPTOR_ID:
		return new TCDescFrequencyList;

	case TCDescScheduling::DESCRIPTOR_ID :
		return new TCDescScheduling;

	case TCDescComponent::DESCRIPTOR_ID:
		return new TCDescComponent(TCDescComponent::TARGET_LOCATION_DVB);

	case TCDescServiceList::DESCRIPTOR_ID:
		return new TCDescServiceList;

	case TCDescDataBroadcastId::DESCRIPTOR_ID:
		return new TCDescDataBroadcastId;

	case TCDescSSULocation::DESCRIPTOR_ID:
		return new TCDescSSULocation;

	case TCDescSatelliteDeliverySystem::DESCRIPTOR_ID:
		return new TCDescSatelliteDeliverySystem;

	case TCDescCRID::DESCRIPTOR_ID:
		return new TCDescCRID;

	case TCDescDefaultAuthority::DESCRIPTOR_ID:
		return new TCDescDefaultAuthority;

	case TCDescExtension::DESCRIPTOR_ID:
		return TCDescExtension::ProcessExtensionDescriptor(pData);

	case TCDescFTAContentManagement::DESCRIPTOR_ID:
		return new TCDescFTAContentManagement;

	case TCDescServiceIdentifier::DESCRIPTOR_ID:
		return new TCDescServiceIdentifier;


	case TCDescDataBroadcast::DESCRIPTOR_ID:
		return new TCDescDataBroadcast;
#endif

	case TCDescMetadataPointer::DESCRIPTOR_ID:
		return new TCDescMetadataPointer;

	default :
		return t_ProcessPrivateDesc(tag,pds);
	}
	return NULL;
}

TCBaseDesc* TCDescConfDVB::t_ProcessPrivateDesc(int tag,unsigned long pds)
{
    #if 0
	if (tag >= TCDescriptorDVB::PRIVATE_DESC_START_TAG && tag < TCDescriptorDVB::PRIVATE_DESC_END_TAG)
	{
		TIMWBinder* MWBinder = TIMWBinder::GetMWBinder();
		INT_ASSERT(MWBinder);

		unsigned long outPds = pds;
		//
		// FrevieewNZSat broadcasts wrong value of PDS (same as Nordig, but desc syntax is compliant with EBook).
		// FreeviewNZSat cannot fix on-air signalling now, although it's against DVB spec, so SW hack is required.
		// The hack is to overwrite PDS coming from stream to the right one (taken from country spec).
		//
		if( pds == DVB_PDSD_INIT
			|| MWBinder->GetDVBSpecCode( (TCWindow::EWindow)t_windowId ) == DVBSPEC_FREEVIEWNZ_SAT )
		{
			outPds = MWBinder->GetPrivateDataSpecification((TCWindow::EWindow)t_windowId);
		}

		switch (outPds)
		{
		case DVB_PDSD_UK_FSAT:
			return m_NewFSatPrivateDesc(tag, outPds);

		case DVB_PDSD_UK_DTT :
			return m_NewDbookPrivateDesc(tag, outPds);

		case DVB_PDSD_EACEM :
			return m_NewEbookPrivateDesc(tag, outPds);

		case DVB_PDSD_FRANCE_TELECOM :
		case DVB_PDSD_TELE_DENMARK :
		case DVB_PDSD_CABO_PORTU :
			return m_NewSagemPrivateDesc(tag, outPds);

		case DVB_PDSD_NORDIG :
		case DVB_PDSD_SWEDISH :
		case DVB_PDSD_SINGAPORE:
			return m_NewNordicPrivateDesc(tag, outPds);

		case DVB_PDSD_CANAL_PLUS:
		case 0xc0:	//TODO: temporary fix - this value is broadcast, although it is inappropriate one; operator shall fix that
			return m_NewTNTSATPrivateDesc(tag, outPds);

		case DVB_PDSD_DIGITAL_PLUS:
			return m_NewDigitalPlusPrivateDesc( tag, outPds );

		case DVB_PDSD_DIGITURK:
			return m_NewDigiturkPrivateDesc( tag, outPds );

		case DVB_PDSD_CI_PLUS:
			return m_NewCIPlusPrivateDesc( tag, outPds );

		case DVB_PDSD_DSMART:
			return m_NewDSmartPrivateDesc( tag, outPds );

		case DVB_PDSD_FRANSAT:
			return m_NewFransatPrivateDesc( tag, outPds );

		case DVB_PDSD_NUMERICABLE:
			return m_NewNumericablePrivateDesc(tag, outPds);

		case DVB_PDSD_KDG:
			return m_NewKDGPrivateDesc(tag, outPds);

		case DVB_PDSD_NEWZEALAND :
		case DVB_PDSD_TELENET:
		case DVB_PDSD_CYFRA_PLUS:
		case DVB_PDSD_NNK:
		default :
			return t_NewDefaultPrivateDesc(tag, outPds);
		}
	}
	else
        #endif
	{
		return new TCDescDefault(tag);
	}

	return 0;
}

#if 0
TCBaseDesc* TCDescConfDVB::m_NewCIPlusPrivateDesc( int tag, unsigned long basePDSD )
{

	switch (tag)
	{
	case TCDescCIPlusService::DESCRIPTOR_ID:
		return new TCDescCIPlusService;

	case TCDescCIPlusContentLabel::DESCRIPTOR_ID:
		return new TCDescCIPlusContentLabel;

	default:
		return t_NewDefaultPrivateDesc(tag, basePDSD);
	}
}

TCBaseDesc* TCDescConfDVB::m_NewAstraPrivateDesc(int tag, unsigned long basePDSD)
{
	switch (tag)
	{
		case TCDescAstraBouquetList::DESCRIPTOR_ID:
			return new TCDescAstraBouquetList;

		case TCDescAstraServiceListName::DESCRIPTOR_ID:
		{
				return new TCDescAstraServiceListName;
		}

		case TCDescAstraVirtualServiceId::DESCRIPTOR_ID:
			return new TCDescAstraVirtualServiceId;

		case TCDescCAIdentifier::DESCRIPTOR_ID:
			// Although this is DVB descriptor it is processed here as it is used only in Astra HD+ receiver mode.
			return new TCDescCAIdentifier;

		default:
			return t_NewDefaultPrivateDesc(tag, basePDSD);
	}
}


TCBaseDesc* TCDescConfDVB::m_NewTNTSATPrivateDesc(int tag, unsigned long basePDSD)
{
	switch (tag)
	{
	case TCDescCanalPlusServicePlanSelection::DESCRIPTOR_ID:
		return new TCDescCanalPlusServicePlanSelection;

	case TCDescCanalPlusRegionalisationPool::DESCRIPTOR_ID:
		return new TCDescCanalPlusRegionalisationPool;

	case TCDescLogicalChannel::HD_SIMULCAST_DESCRIPTOR_ID:
		return new TCDescLogicalChannel(TCDescLogicalChannel::HD_SIMULCAST_DESCRIPTOR_ID, basePDSD);

	default:
		return t_NewDefaultPrivateDesc(tag, basePDSD);
	}
}


TCBaseDesc* TCDescConfDVB::m_NewDigitalPlusPrivateDesc( int tag, unsigned long basePDSD )
{
	switch( tag )
	{
		case TCDescSogecablePrivateChannelList::DESCRIPTOR_ID_REG:
		case TCDescSogecablePrivateChannelList::DESCRIPTOR_ID_CIP:
			return new TCDescSogecablePrivateChannelList( tag );

		default:
			return t_NewDefaultPrivateDesc( tag, basePDSD );
	}
}


TCBaseDesc*
TCDescConfDVB::m_NewDigiturkPrivateDesc( int tag, unsigned long basePDSD )
{
	switch( tag )
	{
		case TCDescLogicalChannel::PHILIPS_LOGICAL_CHANNEL_DESCRIPTOR_ID:
			return new TCDescLogicalChannel( tag, basePDSD );

		case TCDescDigiturkLogicalChannel::DESCRIPTOR_ID:
			return new TCDescDigiturkLogicalChannel( basePDSD );

		case TCDescDigiturkAlternativeFrequency::DESCRIPTOR_ID:
			return new TCDescDigiturkAlternativeFrequency();

		case TCDescDigiturkServiceTheme::DESCRIPTOR_ID:
			return new TCDescDigiturkServiceTheme();

		default:
			return t_NewDefaultPrivateDesc( tag, basePDSD );
	}
	return 0;
}


TCBaseDesc*
TCDescConfDVB::m_NewDSmartPrivateDesc( int tag, unsigned long basePDSD )
{
	switch( tag )
	{
		case TCDescLogicalChannel::DSMART_LOGICAL_CHANNEL_DESCRIPTOR_ID:
			return new TCDescLogicalChannel( tag, basePDSD );

		case TCDescDSmartSatelliteDeliverySystem::DESCRIPTOR_ID:
		case TCDescDSmartSatelliteDeliverySystem::DESCRIPTOR_S2_ID:
			return new TCDescDSmartSatelliteDeliverySystem( tag );

		default:
			return t_NewDefaultPrivateDesc( tag, basePDSD );
	}
	return 0;
}

TCBaseDesc*
TCDescConfDVB::m_NewNumericablePrivateDesc( int tag, unsigned long basePDSD )
{
	switch( tag )
	{
		case TCDescLogicalChannel::NUMERICABLE_LOGICAL_CHANNEL_DESCRIPTOR_ID:
			return new TCDescLogicalChannel( tag, basePDSD );

		default:
			return t_NewDefaultPrivateDesc( tag, basePDSD );
	}
	return 0;
}

TCBaseDesc*
TCDescConfDVB::m_NewFransatPrivateDesc( int tag, unsigned long basePDSD )
{
	switch( tag )
	{
		case TCDescEutelsatChannelNumber::DESCRIPTOR_ID:
			return new TCDescEutelsatChannelNumber();

		default:
			return t_NewDefaultPrivateDesc( tag, basePDSD );
	}
	return 0;
}


TCBaseDesc* TCDescConfDVB::m_NewFSatPrivateDesc(int tag, unsigned long basePDSD)
{
	switch (tag)
	{
	case TCDescFSatTunnelledData::DESCRIPTOR_ID:
		return new TCDescFSatTunnelledData;

	case TCDescFSatAltTunnelledData::DESCRIPTOR_ID:
		return new TCDescFSatAltTunnelledData;

	case TCDescFSatLinkage::DESCRIPTOR_ID:
		return new TCDescFSatLinkage;

	case TCDescFSatLogicalChannel::DESCRIPTOR_ID:
		return new TCDescFSatLogicalChannel;

	case TCDescFSatRegionName::DESCRIPTOR_ID:
		return new TCDescFSatRegionName;

	case TCDescFSatServiceGroup::DESCRIPTOR_ID:
		return new TCDescFSatServiceGroup;

	case TCDescFSatInteractiveStorage::DESCRIPTOR_ID:
		return new TCDescFSatInteractiveStorage;

	case TCDescFSatInfoLocation::DESCRIPTOR_ID:
		return new TCDescFSatInfoLocation;

	case TCDescFSatServiceGroupName::DESCRIPTOR_ID:
		return new TCDescFSatServiceGroupName;

	case TCDescFSatShortServiceName::DESCRIPTOR_ID:
		return new TCDescFSatShortServiceName;

	case TCDescFSatGuidance::DESCRIPTOR_ID:
		return new TCDescFSatGuidance;

	case TCDescFSatInteractiveRestriction::DESCRIPTOR_ID:
		return new TCDescFSatInteractiveRestriction;

	case TCDescFSatContentManagement::DESCRIPTOR_ID:
		return new TCDescFSatContentManagement;

	default :
		return t_NewDefaultPrivateDesc(tag, basePDSD);
	}
	return 0;
}

TCBaseDesc* TCDescConfDVB::m_NewDbookPrivateDesc(int tag, unsigned long basePDSD)
{
	switch (tag)
	{
	case TCDescUKDTTServiceAttribute::DESCRIPTOR_ID:
		return new TCDescUKDTTServiceAttribute;

	case TCDescLogicalChannel::HD_SIMULCAST_DESCRIPTOR_ID:
		return new TCDescLogicalChannel(TCDescLogicalChannel::HD_SIMULCAST_DESCRIPTOR_ID, basePDSD);

	case TCDescGuidance::DESCRIPTOR_ID:
		return new TCDescGuidance;

	default :
		return t_NewDefaultPrivateDesc(tag, basePDSD);
	}
	return 0;
}

TCBaseDesc* TCDescConfDVB::m_NewNordicPrivateDesc(int tag, unsigned long  basePDSD)
{
	switch (tag)
	{
	case TCDescLogicalChannelV2::DESCRIPTOR_ID:
		return new TCDescLogicalChannelV2;

	default :
		return t_NewDefaultPrivateDesc(tag, basePDSD);
	}
	return 0;
}


TCBaseDesc* TCDescConfDVB::m_NewEbookPrivateDesc(int tag, unsigned long  basePDSD)
{
	switch (tag)
	{
	case TCDescLogicalChannel::HD_SIMULCAST_DESCRIPTOR_ID:
		return new TCDescLogicalChannel(TCDescLogicalChannel::HD_SIMULCAST_DESCRIPTOR_ID, basePDSD);

	default :
		return t_NewDefaultPrivateDesc(tag, basePDSD);
	}
	return 0;
}

TCBaseDesc* TCDescConfDVB::m_NewSagemPrivateDesc(int tag, unsigned long  basePDSD)
{
	switch (tag)
	{
	case TCDescLogicalChannel::SAGEM_LOGICAL_CHANNEL_DESCRIPTOR_ID:
		return new TCDescLogicalChannel(TCDescLogicalChannel::SAGEM_LOGICAL_CHANNEL_DESCRIPTOR_ID, basePDSD);

	default :
		return t_NewDefaultPrivateDesc(tag, basePDSD);
	}
	return 0;
}

TCBaseDesc* TCDescConfDVB::m_NewKDGPrivateDesc(int tag, unsigned long  basePDSD)
{
	switch (tag)
	{
	case TCDescRelocatedTS::DESCRIPTOR_ID:
		return new TCDescRelocatedTS;

	default :
		return t_NewDefaultPrivateDesc(tag, basePDSD);
	}
	return 0;
}

TCBaseDesc* TCDescConfDVB::t_NewDefaultPrivateDesc(int tag, unsigned long  basePDSD)
{
    #if 0
	switch (tag)
	{
	case TCDescLogicalChannel::LOGICAL_CHANNEL_DESCRIPTOR_ID:
		return new TCDescLogicalChannel(TCDescLogicalChannel::LOGICAL_CHANNEL_DESCRIPTOR_ID, basePDSD);

	default:
		break;
	}
    #endif
	return NULL;
}
#endif

