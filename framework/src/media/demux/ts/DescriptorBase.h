#ifndef __DSPMW_DESCRIPTOR_BASE_H__
#define __DSPMW_DESCRIPTOR_BASE_H__

#include "DescriptorHash.h"

class TCBaseDesc;
class TCDescConfBase;

//! DescriptorBase class
class TCDescriptorBase
{
private :
	unsigned long m_cachedPDSD;
protected:

    virtual TCDescConfBase* t_GetDescConf(unsigned char tableId) = 0;

    /// \brief This function is called before parsing, it initializes the
    ///        element for parsing.
	virtual void				t_InitParse(void);

    /// \brief Check whether the current descriptor could be added or not, and
    ///        get private data specifier for current descriptor.
    /// \remark outPds is used at DVB configuration, in TCDescriptorBase, we
    ///         only return true.
    /// \param [in] tag the descriptor tag from descriptor raw data.
    /// \param [in] pData  descriptor raw data for parsing.
    /// \param [out] outPds  Get private data specifier for current descriptor.
    /// \retval true current descriptor must be added in the current
    ///              descriptor list. <br>
    /// \retval false current descriptor must not be added in the current
    ///               descriptor list. <br>
    virtual bool t_CheckAddingDesc(int tag, unsigned char* pData,
                                   unsigned long& outPds);

	/// Checks if the content descriptor uses user defined types, and if the
	/// current profile allows the descriptor to be used in this case.  For
	/// instance, the Freesat profile states that the descriptor must be
	/// preceded by a Freesat PDSD to be valid.
	/// @param [in] desc a pointer to the descriptor to verify.
	/// @param [in] curr_pds the current private data specifier descriptor in
	///             scope.
    virtual bool t_checkContentDescriptor(TCBaseDesc* desc,
                                          unsigned long curr_pds)
	{ return true; }


	/**
	 * @brief Check if linkage descriptor should be added to descriptor list.
	 * @remarks If linkage type is private, descriptor should be used only when preceeded 
	 * 	with appropriate private data specifier.
	 * @param [in] pDesc Descriptor.
	 * @param [in] currPds Current private data specifier.
	 * @return True if linkage descriptor should be added to descriptors list.
	 */
	virtual bool t_CheckLinkageDescriptor( TCBaseDesc* pDesc, unsigned long currPds ) { return true; }

public:

    //! Constructor
    TCDescriptorBase();
    //! Destructor
    virtual ~TCDescriptorBase();

    /// \brief      Descriptor Data�� Parsing�� ��� ����Ѵ�.
    /// \remarks    data�� Parsing�Ͽ��� descList�� �����Ѵ�.
    /// \param [in]  data    : Parsing�� �ϱ� ���� Descriptor Raw Data
    /// \param [in]  size     : pData�� Size
    /// \param [out] descList : ����� Descriptor List --> Parsing��
    ///                         Descriptor ��ü�� List�� ����ȴ�.
    /// \param [in] tableId  the table ID of the table containining this
    ///                      data.
    /// \return     Parsing�� pData�� Length.
    /// \par        Example:
    /// \code
    ///            TCDescriptor desc;
    ///            TCDescriptorHash appDescHash;
    ///            appDescHash.Create(TCDescriptor::DEFAULT_NUM_OF_DESC);
    ///            desc.Parse(pData,length, &appDescHash);
    /// \endcode
    /// \see ParseByCount(unsigned char* data, int size, TCDescriptorHash& descList)
    virtual int Parse(unsigned char* data, int size,
                      TCDescriptorHash& descList, unsigned char tableId);

    /// \brief      Descriptor Data�� count ������ŭ Parsing�� ��� ����Ѵ�.
    /// \remarks    data�� Count ������ŭ Parsing�Ͽ��� descList�� �����Ѵ�.
    /// \param [in]  data      Parsing�� �ϱ� ���� Descriptor Raw Data
    /// \param [in]  count      Parsing�Ǵ� Descriptor�� ����... Parsing�� ����Ǹ� descList�� Size�� �����ϰ� �ȴ�.
    /// \param [out]  descList ����� Descriptor List --> Parsing��
    ///                          Descriptor ��ü�� List�� ����ȴ�.
    /// \param [in] tableId  the table ID of the table containining this
    ///                      data.
    /// \return     Parsing�� pData�� Length.
    /// \par        Example:
    /// \code
    ///             TCDescriptor desc;
    ///             int descriptorsCount = 5;
    ///             TCDescriptorHash appDescHash;
    ///             appDescHash.Create(TCDescriptor::DEFAULT_NUM_OF_DESC);
    ///             desc.ParseByCount(pData,descriptorsCount, &appDescHash);
    /// \endcode
    /// \see
    ///             Parse(unsigned char* data, int size, TCDescriptorHash& descList)
    virtual int ParseByCount(unsigned char* data, int count,
                             TCDescriptorHash& descList, unsigned char tableId);


    virtual bool SetCachedPDSD(unsigned long pdsd) { m_cachedPDSD = pdsd; return true;}
};

#endif /* __DSPMW_DESCRIPTOR_BASE_H__ */

