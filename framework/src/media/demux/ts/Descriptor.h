#ifndef __DESCRIPTOR_H__
#define __DESCRIPTOR_H__

#include "DescriptorHash.h"

class TCDescriptorBase;

class TCDescriptor
{

private:
    TCDescriptorBase* m_pImp;

public:
    enum
    {
        DEFAULT_NUM_OF_DESC = 5,
    };

public:

    /// Constructor
	TCDescriptor();

    /// Destructor, virtual so any derived class destructors are called
    /// correctly.
    virtual ~TCDescriptor();

    /// \brief      Descriptor Data�� Parsing�� ��� ����Ѵ�.
    /// \remarks    data�� Parsing�Ͽ��� descList�� �����Ѵ�.
    /// \param [in]  data Parsing�� �ϱ� ���� Descriptor Raw Data
    /// \param [in]  size pData�� Size
    /// \param [out] descList  ����� Descriptor List --> Parsing��
    ///                         Descriptor ��ü�� List�� ����ȴ�.
    /// \param [in] tableId  the table ID of the table containining this
    ///                      data.
    /// \return     Parsing�� pData�� Length.
    /// \par        Example:
    /// \code
    ///            TCDescriptor desc;
    ///            TCDescriptorHash appDescHash;
    ///            appDescHash.Create(TCDescriptor::DEFAULT_NUM_OF_DESC);
    ///            desc.Parse(pData,length, appDescHash);
    /// \endcode
    /// \see ParseByCount(unsigned char* data, int size, TCDescriptorHash& descList)
    int Parse(unsigned char* data, int size, TCDescriptorHash& descList,
              unsigned char tableId);

    ///  \brief      Descriptor Data�� count ������ŭ Parsing�� ��� ����Ѵ�.
    ///  \remarks    data�� Count ������ŭ Parsing�Ͽ��� descList�� �����Ѵ�.
    ///  \param [in]  pData  Parsing�� �ϱ� ���� Descriptor Raw Data
    ///  \param [in]  count  Parsing�Ǵ� Descriptor�� ����... Parsing�� ����Ǹ� descList�� Size�� �����ϰ� �ȴ�.
    ///  \param [out]  descList  ����� Descriptor List --> Parsing��
    ///                           Descriptor ��ü�� List�� ����ȴ�.
    /// \param [in] tableId  the table ID of the table containining this
    ///                      data.
    ///  \return     Parsing�� pData�� Length.
    ///  \par        Example:
    ///  \code
    ///  TCDescriptor desc;
    ///  int descriptorsCount = 5;
    ///  TCDescriptorHash appDescHash;
    ///  appDescHash.Create(TCDescriptor::DEFAULT_NUM_OF_DESC);
    ///  desc.ParseEx(pData, descriptorsCount, appDescHash);
    ///  \endcode
    ///  \see Parse(unsigned char* data, int size, TCDescriptorHash& descList)
    int ParseByCount(unsigned char* data, int count, TCDescriptorHash& descList,
                     unsigned char tableId);

   bool SetCachedPDSD(unsigned long pdsd);
};

#endif /* __DESCRIPTOR_H__ */

