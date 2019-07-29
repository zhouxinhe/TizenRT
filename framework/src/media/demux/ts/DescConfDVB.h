
#ifndef __DSPMW_DESC_CONF_DVB_H__
#define __DSPMW_DESC_CONF_DVB_H__

#include "DescConfBase.h"

class TCDescConfDVB : public TCDescConfBase
{
public:
	TCDescConfDVB();
	virtual TCBaseDesc* NewDescriptor(int tag, const unsigned char *pData, unsigned long pds);

protected :
	virtual TCBaseDesc* t_ProcessPrivateDesc(int tag,unsigned long pdsd);

	TCBaseDesc* t_NewDefaultPrivateDesc(int tag, unsigned long  basePDSD);

#if 0
private :
	TCBaseDesc* m_NewDbookPrivateDesc(int tag, unsigned long  basePDSD);
	TCBaseDesc* m_NewEbookPrivateDesc(int tag, unsigned long  basePDSD);
	TCBaseDesc* m_NewNordicPrivateDesc(int tag, unsigned long  basePDSD);
	TCBaseDesc* m_NewSagemPrivateDesc(int tag, unsigned long  basePDSD);
	TCBaseDesc* m_NewFSatPrivateDesc(int tag, unsigned long basePDSD);
	TCBaseDesc* m_NewKDGPrivateDesc(int tag, unsigned long  basePDSD);

	/**
	 * @fn TCBaseDesc* m_NewAstraPrivateDesc( int tag, unsigned long basePDSD )
	 * @brief Create private Astra descriptors.
	 * @param [in] tag Descriptor tag.
	 * @param [in] basePDSD Private data specifier value for Astra.
	 * @return Requested Astra private descriptor.
	 */
	TCBaseDesc* m_NewAstraPrivateDesc( int tag, unsigned long basePDSD);

	/**
	 * @brief Create private TNTSAT descriptors.
	 * @param [in] tag Descriptor tag.
	 * @param [in] basePDSD Private data specifier value for TNTSAT.
	 * @return Requested TNTSAT private descriptor.
	 */
	TCBaseDesc* m_NewTNTSATPrivateDesc( int tag, unsigned long basePDSD );

	/**
	 * @brief Create private Digital+ descriptors.
	 * @param [in] tag Descriptor tag.
	 * @param [in] basePDSD Private data specifier value for Digital+.
	 * @return Requested Digital+ private descriptor.
	 */
	TCBaseDesc* m_NewDigitalPlusPrivateDesc( int tag, unsigned long basePDSD );

    /**
	 * @brief Create private Digiturk descriptors.
	 * @param [in] tag Descriptor tag.
	 * @param [in] basePDSD Private data specifier value for Digiturk.
	 * @return Requested Digiturk private descriptor.
	 */
	TCBaseDesc* m_NewDigiturkPrivateDesc( int tag, unsigned long basePDSD );

    /**
	 * @brief Create private D-Smart descriptors.
	 * @param [in] tag Descriptor tag.
	 * @param [in] basePDSD Private data specifier value for D-Smart.
	 * @return Requested D-Smart private descriptor.
	 */
	TCBaseDesc* m_NewDSmartPrivateDesc( int tag, unsigned long basePDSD );

	/**
	 * @brief Create private CI Plus descriptors.
	 * @param [in] tag Descriptor tag.
	 * @param [in] basePDSD Private data specifier value for CI Plus.
	 * @return Requested CI Plus private descriptor.
	 */
	TCBaseDesc* m_NewCIPlusPrivateDesc( int tag, unsigned long basePDSD );

        /**
	 * @brief Create private Numericable descriptors.
	 * @param [in] tag Descriptor tag.
	 * @param [in] basePDSD Private data specifier value for Numericable.
	 * @return Requested Numericable private descriptor.
	 */
	TCBaseDesc* m_NewNumericablePrivateDesc( int tag, unsigned long basePDSD );

    /**
	 * @brief Create private Fransat descriptors.
	 * @param [in] tag Descriptor tag.
	 * @param [in] basePDSD Private data specifier value for Fransat.
	 * @return Requested Fransat private descriptor.
	 */
	TCBaseDesc* m_NewFransatPrivateDesc( int tag, unsigned long basePDSD );
#endif
};



#endif /* __DSPMW_DESC_CONF_DVB_H__ */

