
#include "DescMetadataPointer.h"
#include "DTVmwType.h"

//------------------------------------------------------------------------------

#define GET8(BUFFER)  ((BUFFER)[0])
#define GET16(BUFFER) (((BUFFER)[0] <<  8) | ((BUFFER)[1]))
#define GET32(BUFFER) (((BUFFER)[0] << 24) | ((BUFFER)[1] << 16) | \
                       ((BUFFER)[0] <<  8) | ((BUFFER)[1]))

//------------------------------------------------------------------------------



/// Broadcast record List specific application format
const unsigned short VALID_APPLICATION   = 0x0101;

/// Broadcast Record List specific metadata format
const unsigned char  VALID_MD_APP_FORMAT = 0x3F;

/// Broadcast record List specific service id
const unsigned char  VALID_SERVICE_ID    = 0xFF;

TCDescMetadataPointer::TCDescMetadataPointer()
	: TCBaseDesc(DESCRIPTOR_ID)
	, m_appFormat(0)
	, m_appFormatId(0)
	, m_format(0)
	, m_formatId(0)
	, m_serviceId(0)
	, m_carriageFlags(0)
	, m_locatorRecFlag(0)
	, m_validMetadataPtr(false)
{
	m_triplet.onid      = INVALID;
	m_triplet.tsid      = INVALID;
	m_triplet.serviceid = INVALID;
}

int TCDescMetadataPointer::t_Parse(unsigned char* data, unsigned char len)
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
		return 0;
	}

	if(m_appFormat == 0xFFFF)
	{
		if(ptr + 4 <= end)
		{
			m_appFormatId = GET32(ptr);
			ptr += 4;
		}
		else
		{
			return 0;
		}
	}

	if(ptr < end)
	{
		m_format = GET8(ptr);
		ptr++;
	}
	else
	{
		return 0;
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
			return 0;
		}
	}

	if(ptr < end)
	{
		m_serviceId = GET8(ptr);
		ptr++;
	}
	else
	{
		return 0;
	}

	if(ptr < end)
	{
		tmp = GET8(ptr);
		ptr++;
	}
	else
	{
		return 0;
	}

	m_locatorRecFlag = (tmp >> 7) & 0x01;
	m_carriageFlags   = (tmp >> 5) & 0x03;

	if(m_locatorRecFlag == 1)
	{
		if(ptr < end)
		{
			tmp = GET8(ptr);
			if(ptr + tmp + 1 <= end)
			{
				m_locatorRec.assign(ptr + 1, tmp);
				ptr += tmp + 1;
			}
			else
			{
				return 0;
			}
		}
		else
		{
			return 0;
		}
	}

	if(ptr < end)
	{
	if(m_carriageFlags != 0x03)
		{
			if(ptr + 2 <= end)
				{
					m_triplet.serviceid = GET16(ptr);
					ptr += 2;
				}
				else
				{
					return 0;
				}
		}

	if( m_carriageFlags == 0x01)
				{
			if(ptr +4 <= end)
			{
				m_triplet.onid = GET16(ptr);
				ptr += 2;
				m_triplet.tsid = GET16(ptr);
					ptr += 2;
				}
				else
				{
					return 0;
				}
		}

	}
	else
	{
		return 0;
	}

	if(ptr < end)
	{
		m_private.assign(ptr, end - ptr);
	}
	else if(end < ptr)
	{
		return 0;
	}

	if( m_appFormat == VALID_APPLICATION &&
		m_format     == VALID_MD_APP_FORMAT &&
		m_serviceId == VALID_SERVICE_ID &&
		!m_locatorRecFlag )
	{
		m_validMetadataPtr = true;
	}

	return len;
}


bool TCDescMetadataPointer::GetLocatorRec(std::string& loc) const
{
	if(!m_validMetadataPtr)
	{
		return false;
	}
	loc = m_locatorRec;
	return true;
}

bool TCDescMetadataPointer::GetTriplet(TCServiceKey& triplet) const
{
	if(!m_validMetadataPtr)
	{
		return false;
	}
	if(m_carriageFlags == 1)
	{
		triplet = m_triplet;
	}
	else
	{
		// Preserve the rest which was not set by this descriptor.
		triplet.serviceid = m_triplet.serviceid;
	}
	return true;
}


const std::string& TCDescMetadataPointer::UserData() const
{
	if(!m_validMetadataPtr)
	{
		static const std::string empty;
		return empty;
	}
	return m_private;
}


void TCDescMetadataPointer::DeleteAll(void)
{
	m_appFormat = 0;
	m_appFormatId = 0;
	m_format = 0;
	m_formatId = 0;
	m_serviceId = 0;
	m_validMetadataPtr = false;

	m_triplet.onid      = INVALID;
	m_triplet.tsid      = INVALID;
	m_triplet.serviceid = INVALID;

	m_locatorRec.clear();
	m_private.clear();
}


TCBaseDesc* TCDescMetadataPointer::Fork(void)
{
	TCDescMetadataPointer* pCopy = new TCDescMetadataPointer();

	if (t_descBufferSize > 0 && pCopy)
	{
		pCopy->SetTableId(t_tableId);
		pCopy->Parse(t_pDescBuffer);
	}

	return (TCBaseDesc*)(pCopy);
}

