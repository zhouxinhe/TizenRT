
#ifndef _DESCMETADATAPOINTER_H_
#define _DESCMETADATAPOINTER_H_

#include <string>
#include "BaseDesc.h"

class TCServiceKey
{
public:
	unsigned short onid;
	unsigned short tsid;
	unsigned short serviceid;
};

/// Metadata Pointer Descriptor Parser, based on description in
/// "ISO/IEC 13818-1-2007E"
class TCDescMetadataPointer : public TCBaseDesc
{

public:
    enum
    {
        DESCRIPTOR_ID = 0x25,
    };

    TCDescMetadataPointer();

    ~TCDescMetadataPointer() {}

    /// DEPRECATED - Use IsValidMetadataPtr
    /// Checks if the extacted data matches the RecordList requirements
    ///
    /// @return true if this descriptor satisfies the record list
    ///         requirements
    bool IsValidForRecList(void) const
        { return m_validMetadataPtr;}

    /// Checks if the extacted data matches the RecordList requirements
    ///
    /// @return true if this descriptor satisfies the record list
    ///         requirements
    bool IsValidMetadataPtr(void) const
        { return m_validMetadataPtr; }

    /// Gets the Application format
    ///
    /// @return the applciation format code
    unsigned short AppFormat() const
        { return m_appFormat; }

    /// Gets the Application format identifier
    ///
    /// @return application format identifier
    unsigned long AppFormatIdentifier() const
        { return m_appFormatId; }

    /// Gets the format.
    ///
    /// @return the format code
    unsigned char Format() const
        { return m_format; }

    /// Gets the format identifier.
    ///
    /// @return format identifier
    unsigned long FormatIdentidier() const
        { return m_formatId; }

    /// Gets the service id.
    ///
    /// @return Service Id
    unsigned short ServiceId() const
        { return m_serviceId; }

    /// Get the location described as string.
    ///
    /// @param [out] loc  Location where to find a specific service
    ///
    /// @return true on success, false otherwise.
    bool GetLocatorRec(std::string& loc) const;

    /// Get the location as triplet.
    ///
    /// @param [out] triplet  DVB-triplet that describes a specific service
    ///
    /// @return true on success, false otherwise.
    bool GetTriplet(TCServiceKey& triplet) const;

    /// Gets the user data.
    ///
    /// @return string that encapsulates the user data, maybe empty
    const std::string& UserData() const;

	/**
	 * @see Base class.
	 **/
    virtual void DeleteAll(void);

	/**
	 * @see Base class.
	 **/
    virtual TCBaseDesc* Fork(void);

protected:

    /**
	 * @see Base class.
	 **/
    int t_Parse(unsigned char* data, unsigned char len);

private:
    /// The metadata_application_format is a 16-bit field that specifies the
    /// application responsible for defining usage, syntax and semantics of
    /// the metadata_locator_record record and any other privately defined
    /// fields in this descriptor. The coding of this field is defined in
    /// Table 2-81 in 2.6.57.
    unsigned short m_appFormat;

    /// The coding of this field is defined in subclause 2.6.57.
    unsigned long m_appFormatId;

    /// The metadata_format is an 8-bit field that indicates the format and
    /// coding of the metadata. The coding of this field is specified in
    /// Table 2-84.
    unsigned char m_format;

    /// The coding of this 32-bit field is fully equivalent to the coding of
    /// the format_identifier field in the registration_descriptor, as
    /// defined in 2.6.8.
    unsigned long m_formatId;

    /// This 8-bit field references the metadata service. It is used for
    /// retrieving a metadata service from within a metadata stream.
    unsigned char m_serviceId;

    /// The MPEG_carriage_flags is a 2-bit field which specifies if the
    /// metadata stream containing the associated metadata service is
    /// carried in an ITU-T Rec. H.222.0 | ISO/IEC 13818-1 stream, and if
    /// so, whether the associated metadata is carried in a Transport Stream
    /// or Program Stream. The coding of this field is defined in Table
    /// 2-85.
    unsigned char m_carriageFlags;

    /// The metadata_locator_record_flag is a 1-bit field which, when set to
    /// '1' indicates that associated metadata is available on a location
    /// outside of an ITU-T Rec. H.222.0 | ISO/IEC 13818-1 stream, specified
    /// in a metadata_locator_record.
    unsigned char m_locatorRecFlag;

    /// The metadata_locator_record_byte is part of a string of one or more
    /// contiguous bytes that form the metadata locator record. This record
    /// specifies one or more locations outside of an ITU-T Rec. H.222.0 |
    /// ISO/IEC 13818-1 stream. The format of the metadata locator record is
    /// defined by the metadata application signalled by the
    /// metadata_application_format field. The record may for example
    /// contain Internet URLs that specify where the metadata can be found,
    /// possibly in addition to their location(s) in the Transport Stream.
    /// If the MPEG_carriage_flags is coded with the value '0', '1' or '2'
    /// and the metadata locator record is present, then this signals
    /// alternative locations for the same metadata.
    std::string m_locatorRec;

    /// Get the triplet (TSID, ONID and SID) where to find the Metadata
    /// descriptor.
    TCServiceKey m_triplet;

    /// The private_data_byte is an 8-bit field. The private_data_bytes
    /// represent data, the format of which is defined privately. These
    /// bytes can be used to provide additional information as deemed
    /// appropriate.
    std::string m_private;

    /// Cached state id the parsed content is valid for Record List
    /// requirements
    bool m_validMetadataPtr;

};
#endif // _DESCMETADATAPOINTER_H_

