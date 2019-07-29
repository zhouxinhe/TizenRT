/*!
\file TCDescDefault.cpp
\brief Declaration file of class TCDescDefault
 * Summary:	Declaration of class TCDescDefault
 * Classes:	TCDescDefault
 * History:
 *
 */

#include "DTVmwType.h"
#include "DescDefault.h"
/*!
\brief      data�� �Ľ�
\param[in]  data    �Ľ��� ������ �ּ�
\return     �Ľ̵� �������� ����
\remarks    Stuffing Descriptor�� �ƹ��ϵ� ���� �ʱ� ������ ����Ǵ� �Ľ�
            ���̸��� ��ȯ�Ѵ�.
*/
int TCDescDefault::t_Parse(unsigned char* data, unsigned char len)
{
	return t_descriptorLength;
}




/*!
\brief      Constructor
*/
TCDescDefault::TCDescDefault(int tag)
: TCBaseDesc(tag)
{
}

/*!
\brief      Destructor
*/
TCDescDefault::~TCDescDefault(void)
{
	DeleteAll();
}



/*!
\brief      Deletes all of the dynamic memory
\remarks    Deletes all of the dynamic memory
\par        Example:
*/
void TCDescDefault::DeleteAll(void)
{
}




/*!
\brief      �� Ŭ������ ������ Ŭ������ �����ϰ�, �� �ּҸ� ��ȯ
\return     ������ Ŭ������ �ּ�
\remarks    �� Ŭ������ ������ Ŭ������ ���� �޸𸮷� �����ϰ�, ������ Ŭ������
            �ּҸ� ��ȯ�Ѵ�.
*/
TCBaseDesc* TCDescDefault::Fork(void)
{
	TCDescDefault* pCopy = new TCDescDefault(t_descriptorTag);

	if (t_descBufferSize > 0 && pCopy) //sicodereview 2007.6.25
	{
		pCopy->SetTableId(t_tableId);
		pCopy->Parse(t_pDescBuffer);
	}

	return (TCBaseDesc*)(pCopy);
}

