
#include <string.h>
#include "DTVmwType.h"
#include "BaseDesc.h"
//#include "Descriptor.h"

#define DESCRIPTOR_TAG_AND_LENGTH_BYTES 2

/// fetch the descriptor tag from raw descriptor data.
#define t_DescriptorTag(buffer)    buffer[0]
/// Return the descriptor length from raw descriptor data.
#define t_DescriptorLength(buffer) buffer[1]
/// Return the descriptor data (pointer to the start of the actual data)
#define t_DescriptorData(buffer)   &buffer[2]


TCBaseDesc::TCBaseDesc(int descTag) : t_descriptorTag(descTag)
{
	t_pDescBuffer = NULL;
	t_descBufferSize = 0;
	t_descriptorLength = 0;
	t_tableId = -1;
}

TCBaseDesc::~TCBaseDesc()
{
	if (t_pDescBuffer) {
		delete[] t_pDescBuffer;
		t_pDescBuffer = NULL;
	}
}

int TCBaseDesc::Parse(uint8_t* data)
{
	if (t_pDescBuffer) {
		delete[] t_pDescBuffer;
		t_pDescBuffer = NULL;
	}

	t_descriptorLength = t_DescriptorLength(data);
	if (t_descriptorLength > 0)
	{
		t_descBufferSize = DESCRIPTOR_TAG_AND_LENGTH_BYTES + t_descriptorLength;

		t_pDescBuffer = new uint8_t[t_descBufferSize];
		if (t_pDescBuffer == NULL)
		{
			ONLY_ASSERT(0);
			return t_descBufferSize;
		}
		memcpy(t_pDescBuffer, data, t_descBufferSize);

		int descLength = t_Parse(t_DescriptorData(data), t_descriptorLength);
		if (descLength != t_descriptorLength)
		{
			BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::MAJOR, "[Warning] Descriptor[0x%x] length mismatch!inLen=%d, outLen=%d", t_descriptorTag, t_descriptorLength, descLength);
			//ASSERT(descLength == t_descriptorLength); //sicodereview 2007.6.18
		}
	}

	return DESCRIPTOR_TAG_AND_LENGTH_BYTES + t_descriptorLength;
}

int TCBaseDesc::Tag(void)
{
	return t_descriptorTag;
}

uint8_t TCBaseDesc::Length(void)
{
	return DESCRIPTOR_TAG_AND_LENGTH_BYTES + t_descriptorLength;
	// how about return t_descBufferSize; ??
}

bool TCBaseDesc::GetDescriptor(uint8_t *pBuff, int *size)
{
	INT_ASSERT(pBuff != NULL);

	if (t_pDescBuffer == NULL || t_descBufferSize == 0) {
		*size = 0;
		return false;
	}

	if (*size >= t_descBufferSize) {
		memcpy(pBuff, t_pDescBuffer, t_descBufferSize);
		*size = t_descBufferSize;
		return true;
	}

	return false;
}

bool TCBaseDesc::FlagEqual(const TCBaseDesc* pInDesc)
{
	INT_ASSERT(pInDesc);

	TCBaseDesc* pDesc = const_cast<TCBaseDesc*>(pInDesc);

	if (t_descBufferSize != pDesc->t_descBufferSize) {
		return false;
	}

	if (t_pDescBuffer && pInDesc->t_pDescBuffer && t_descBufferSize > 0) {
		if (memcmp(t_pDescBuffer,pInDesc->t_pDescBuffer,t_descBufferSize) != 0) {
			return false;
		}
	}

	return true;
}

