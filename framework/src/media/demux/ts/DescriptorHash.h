#ifndef _DESCRIPTORHASH_H_
#define _DESCRIPTORHASH_H_

#include "DTVmwType.h"
#include <vector>
#include <map>

class TCBaseDesc;
//class PCList;

/// An interface definition to use by classes that need to provided an
/// API to access the data contained in a TCDescriptorHash object.
class IDescriptorContainer
{
protected:
    /// This is an API interface only, delete should not be called on an
    /// object of this type.
    virtual ~IDescriptorContainer() {}

public:
    /// Return the number of descriptors of this type. The tag value is either
    /// a standard descriptor ID, or the value returned by
    /// TCDescExtension::DescriptorID().
    /// @param [in] tag the descriptor tag to query.
    /// @return the number of descriptors of this type stored.
    virtual unsigned int NumOfDescriptors(int tag)  = 0;

    /// Get a pointer to a descriptor of the specified tag.  Optionally provide
    /// the index if there are multiple tags (defaults to the first).
    /// @param [in] tag the descriptor tag we're interested in.
    /// @param [in] index the index position of the tag (if there are multiple
    ///                   descriptors available).
    /// @return a pointer to the descriptor or 0 if the tag or tag + index
    ///         cannot be located.
    virtual TCBaseDesc* Descriptor(int tag, int index = 0) = 0;

    /// Get the total number of descriptors stored.
    virtual int NumOfDescriptors(void) = 0;

    /// Get a descriptor based on its index.
    virtual TCBaseDesc* DescriptorByIndex(int index) = 0;

    /// Get a copy of every descriptor stored.
    /// @param [in] pDesc a pointer to a list to store a copy of each
    ///                   descriptor.
    virtual bool GetDescriptor(PCList* pDesc) = 0;
};

/// A container class to hold a set of descriptors (TCBaseDesc*)
class TCDescriptorHash : public IDescriptorContainer
{
public:
    /// Create this descriptor hash with the specified number of has entries.
    /// @param [in] num the initial number of hash entries to create.
    /// @return true if the hash object is valid.
    bool Create(int num);

    /// Make a copy of a descriptor container - make a full copy of each
    /// descriptor.
    /// @param [in] desc the descriptor hash object to copy.
    TCDescriptorHash& operator=(const TCDescriptorHash& desc);

    /// Free all resources, following this call, FlagCreate() will return
    /// false.
    void Destroy();

    /// return true if the Create method has been called, and Destroy() hasn't!
    bool FlagCreate(void);

    /// Free all objects contained in the hash.
    void DeleteAll(void);

    /// Add a TCBaseDesc object to the container.
    /// @param [in] desc the object to add to the container.
    /// @remarks the container now 'owns' the object - it should not be
    ///          deleted by any other code.
    void Add(TCBaseDesc* desc);

    /// @name API interface from IDescriptorContainer.  This class provides the
    /// IDescriptorContainer API.  Any class that uses this class can then
    /// also derive from IDescriptorContainer to provide a consistent API for
    /// accessing stored descriptors.
    /// @{
    unsigned int NumOfDescriptors(int tag) ;
    TCBaseDesc* Descriptor(int tag, int index = 0);
    int NumOfDescriptors(void) ;
    TCBaseDesc* DescriptorByIndex(int index);
    bool GetDescriptor(PCList* pDesc);

    //virtual ESerializableType GetSerializedType(void){return TISerializable::TYPE_TCDescriptorHash;}
	//virtual bool ClassToTree(TCMarshalTreeBranch& treeParent) ;
	//virtual bool TreeToClass(TCMarshalTreeBranch& treeMine) ;
    /// @}

private:
    /// Use a map (tag) of vectors (descriptors) for simple access that is
    /// visible in good debuggers.  This provides simplicity for the
    /// Descriptor(tag, index) methods.  It is this object that 'owns' the data and
    /// should delete them.
    std::map<int, std::vector<TCBaseDesc*>> m_hash;

    /// Also store pointers to the date in a vector for access from DescriptorByIndex(),
    /// m_list holds just pointers to the objects within m_hash.
    std::vector<TCBaseDesc*> m_list;
};

#endif /* _DESCRIPTORHASH_H_ */
