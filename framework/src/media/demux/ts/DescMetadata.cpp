/**
 * @file	DescMetadata.cpp
 * @brief	Implementation of Metadata descriptor class.
 *
 * Copyright 2013 by Samsung Electronics, Inc.,
 *
 * This software is the confidential and proprietary information
 * of Samsung Electronics, Inc. ("Confidential Information").  You
 * shall not disclose such Confidential Information and shall use
 * it only in accordance with the terms of the license agreement
 * you entered into with Samsung.
 */

#include "BaseDesc.h"

#include "DescMetadata.h"


//------------------------------------------------------------------------------

#define GET8(BUFFER)  ((BUFFER)[0])
#define GET16(BUFFER) (((BUFFER)[0] <<  8) | ((BUFFER)[1]))
#define GET32(BUFFER) (((BUFFER)[0] << 24) | ((BUFFER)[1] << 16) | \
                       ((BUFFER)[0] <<  8) | ((BUFFER)[1]))

//------------------------------------------------------------------------------

TCDescMetadata::TCDescMetadata()
    : TCBaseDesc(DESCRIPTOR_ID)
    , m_appFormat(0)
    , m_appFormatId(0)
    , m_format(0)
    , m_formatId(0)
    , m_serviceId(0)
    , m_decCfgFlag(0)
    , m_dsmccFlag(0)
    , m_validMetadataPtr(false)
{
}


typedef enum EDecCfgFlags
{
    /// No decoder configuration is needed.
    EDEC_CFG_NO_CFG_NEEDED,

    /// The decoder configuration is carried in this descriptor in the
    /// decoder_config_byte field.
    EDEC_CFG_DESC_CFG,

    /// The decoder configuration is carried in the same metadata service as to which
    /// this metadata descriptor applies.
    EDEC_CFG_SAME_CFG,

    /// The decoder configuration is carried in a DSM-CC carousel.
    /// This value shall only be used if the metadata service to which this descriptor
    /// applies is using the same type of DSM-CC carousel.
    EDEC_CFG_DSMCC,

    /// The decoder configuration is carried in another metadata service within the same
    /// program, as identified by the decoder_config_metadata_service_id field in this
    /// metadata descriptor.
    EDEC_CFG_OTHER,

    /// Reserved (1)
    EDEC_CFG_RESERVED_1,

    /// Reserved (2)
    EDEC_CFG_RESERVED_2,

    /// Privately defined.
    EDEC_CFG_PRIVATE
} EDecCfgFlags;

/// Broadcast record List specific application format
const unsigned short VALID_APPLICATION   = 0x0101;

/// Broadcast Record List specific metadata format
const unsigned char  VALID_MD_APP_FORMAT = 0x3F;

/// Broadcast record List specific service id
const unsigned char  VALID_SERVICE_ID    = 0xFF;

/// Broadcast Record List specific configuration flags
const unsigned char  VALID_CFG_FLAGS     = 0x00;

int TCDescMetadata::t_Parse(unsigned char* data, unsigned char len)
{
    const char *start = (const char*)data;
    const char *end   = start + len;
    const char *ptr   = start;

    unsigned char tmp;

    DeleteAll();

    if(ptr + 2 <= end)
    {
        m_appFormat = GET16(ptr);
        ptr += 2;
    }
    else
    {
        return (int)(end - ptr);
    }

    if(m_appFormat == 0xFFFF)
    {
        if(ptr + 4<= end)
        {
            m_appFormatId = GET32(ptr);
            ptr += 4;
        }
        else
        {
            return (int)(end - ptr);
        }
    }

    if(ptr + 1 <= end)
    {
        m_format = GET8(ptr);
        ptr+= 1;
    }
    else
    {
        return (int)(end - ptr);
    }

    if(m_format == 0xFF)
    {
        if(ptr + 4 <= end)
        {
            m_formatId = GET32(ptr);
            ptr += 4;
        }
        else
        {
            return (int)(end - ptr);
        }
    }

    if(ptr + 1 <= end)
    {
        m_serviceId = GET8(ptr);
        ptr+= 1;
    }
    else
    {
        return (int)(end - ptr);
    }

    if(ptr < end)
    {
        tmp = GET8(ptr);
        ptr+=1;
    }
    else
    {
        return (int)(end - ptr);
    }

    m_decCfgFlag = (tmp >> 5) & 0x07;
    m_dsmccFlag   = (tmp >> 4) & 0x01;

    if(m_dsmccFlag == 0x01)
    {
        if(ptr < end)
        {
            tmp = GET8(ptr);
            m_serviceData.assign(ptr + 1, tmp);
            ptr += tmp + 1;
        }
        else
        {
            return (int)(end - ptr);
        }
    }

    if(ptr < end)
    {
        switch(m_decCfgFlag)
        {
            case EDEC_CFG_DESC_CFG:
            case EDEC_CFG_DSMCC:
            case EDEC_CFG_RESERVED_1:
            case EDEC_CFG_RESERVED_2:
                // Shared structure for all type as only one can be set at a
                // given time.
                tmp = GET8(ptr);
                if(ptr + tmp + 1 <= end)
                {
                    m_data.assign(ptr + 1, tmp);
                    ptr += tmp + 1;
                }
                else
                {
                    return (int)(end - ptr);
                }
                break;

            case EDEC_CFG_OTHER:
                {
                    m_serviceId = GET8(ptr);
                    ptr++;
                }
                break;

            default:
                break;
        }
    }

    if(ptr < end)
    {
        m_userData.assign(ptr, end - ptr);
    }
    else if(end < ptr)
    {
        return (int)(end - ptr);
    }

    if( m_appFormat   == VALID_APPLICATION &&
        m_format       == VALID_MD_APP_FORMAT &&
        m_serviceId   == VALID_SERVICE_ID &&
        m_decCfgFlag == VALID_CFG_FLAGS &&
        m_dsmccFlag )
    {
        m_validMetadataPtr = true;
    }

    return len;
}


const std::string& TCDescMetadata::RootDir(void) const
{
    if(!m_validMetadataPtr)
    {
        static const std::string empty;
        return empty;
    }

    return m_serviceData;
}


void TCDescMetadata::DeleteAll(void)
{
    m_appFormat = 0;
    m_appFormatId = 0;
    m_format = 0;
    m_formatId = 0;
    m_serviceId = 0;
    m_decCfgFlag = 0;
    m_dsmccFlag = 0;
    m_validMetadataPtr = false;

    m_serviceData.clear();
    m_data.clear();
    m_userData.clear();
}


TCBaseDesc* TCDescMetadata::Fork(void)
{
    TCDescMetadata* pCopy = new TCDescMetadata;

    if (t_descBufferSize > 0 && pCopy)
    {
		pCopy->SetTableId(t_tableId);
        pCopy->Parse(t_pDescBuffer);
    }

    return (TCBaseDesc*)(pCopy);
}
