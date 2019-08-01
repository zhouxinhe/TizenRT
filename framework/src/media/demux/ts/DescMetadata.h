#ifndef _DESCMETADATA_H_
#define _DESCMETADATA_H_

#include "BaseDesc.h"
#include "DTVmwType.h"
#include <string>

/// Metadata Descriptor Parser, based on description in "ISO/IEC 13818-1-2007E"
class TCDescMetadata : public TCBaseDesc
{

    public:
        enum
        {
            DESCRIPTOR_ID = 0x26,
        };

        TCDescMetadata();

        virtual ~TCDescMetadata() {}

        /// DEPRECATED - Use IsValidMetadataPtr
        /// Checks if the extracted data matches the RecordList requirements
        ///
        /// @return true if this is a valid Record-List.
        bool IsValidForRecList(void) const
            { return m_validMetadataPtr; }

        /// Checks if the extracted data matches the RecordList requirements
        ///
        /// @return true if this is a valid Record-List.
        bool IsValidMetadataPtr(void) const
            { return m_validMetadataPtr; }

        /// This function returns the Root-Directory found in this descriptor.
        ///
        /// @return the Root-Directory found in this descriptor.
        const std::string& RootDir(void) const;

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
        /// the service_identification_record and any privately defined bytes in
        /// this descriptor. The coding of this field is defined in Table 2-81.
        unsigned short m_appFormat;

        /// The coding of this field is defined in 2.6.57.
        unsigned long m_appFormatId;

        /// The coding of this field is defined in 2.6.59.
        unsigned char m_format;

        /// The coding of this field is defined in 2.6.59.
        unsigned long m_formatId;

        /// This 8-bit field identifies the metadata service to which this
        /// metadata descriptor applies.
        unsigned char m_serviceId;

        /// The decoder_config_flags is a 3-bit field which indicates whether
        /// and how decoder configuration information is conveyed.
        unsigned char m_decCfgFlag;

        /// This is a one-bit flag that is set to '1' if the stream with which
        /// this descriptor is associated is carried in an ISO/IEC 13818-6 data
        /// or object carousel.
        unsigned char m_dsmccFlag;

        /// This byte is part of a string of one or more contiguous bytes that
        /// specify the service_identification_record. This record contains data
        /// on retrieval of the metadata service from a DSM-CC carousel. The
        /// format of the metadata locator record is defined by the application
        /// indicated by the metadata application format. When a DSM-CC object
        /// carousel is used, the record may for example comprise the unique
        /// object identifier (the IOP:IOR() from 11.3.1 and 5.7.2.3 of
        /// ISO/IEC 13818-6 DSM-CC) for the metadata service. Similarly, in case
        /// of a DSM-CC data carousel, the record can for example provide the
        /// transaction_id and the module_id of the metadata service.
        std::string m_serviceData;

        /// This field specifies the number of reserved bytes immediately
        /// following.
        std::string m_data;

        /// The userdata that is located at the end of the descriptor.
        std::string m_userData;

        /// Cached state id the parsed content is valid for Record List
        /// and EEPG requirements
        bool m_validMetadataPtr;

};
#endif // _DESCMETADATA_H_

