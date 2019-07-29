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
\brief      data를 파싱
\param[in]  data    파싱할 데이터 주소
\return     파싱된 데이터의 길이
\remarks    Stuffing Descriptor는 아무일도 하지 않기 때문에 예상되는 파싱
            길이만을 반환한다.
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
\brief      본 클래스와 동일한 클래스를 생성하고, 그 주소를 반환
\return     생성된 클래스의 주소
\remarks    본 클래스와 동일한 클래스를 동적 메모리로 생성하고, 생성된 클래스의
            주소를 반환한다.
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

