#ifndef __BASE_DESC_H__
#define __BASE_DESC_H__

#include "DTVmwType.h"

#define s_DESCRIPTOR_TAG_AND_LENGTH_NUM_OF_BYTE 2

class TCBaseDesc
{
protected:

	uint8_t *t_pDescBuffer;
	int t_descBufferSize;

	//! descriptor_tag
	int t_descriptorTag;
	//! descriptor_length
	uint8_t t_descriptorLength;
	//! table id of this descriptor
	int t_tableId;

	//! Constructor
	TCBaseDesc(int descTag);

	virtual int t_Parse(uint8_t *data, uint8_t len) = 0;

public:

	//! Destructor
	virtual ~TCBaseDesc();
	//! Deletes all of the items.
	virtual void DeleteAll(void) = 0;

	virtual TCBaseDesc* Fork(void) = 0;

	int Parse(uint8_t* data);

	/// Returns the descriptor_tag
    /// @remarks The DVB extension descriptor (TCDescExtension) implements
    /// this to return the tag value used in the MW.
	virtual int Tag(void);

	uint8_t Length(void);

	bool GetDescriptor(uint8_t *pBuff, int *size);

	bool FlagEqual(const TCBaseDesc *pDesc);

	void SetTableId(int tableId) { t_tableId = tableId; }
	int TableId(void) { return t_tableId; }
};

#endif /* __BASE_DESC_H__ */
