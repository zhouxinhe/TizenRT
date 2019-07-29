
#include "DTVmwType.h"
#include "Section.h"
#include "BaseSection.h"


int TCBaseSection::t_CheckVersion(int version, int sectionNum, int lastSectionNum, uint32_t crc32)
{
    m_checkSectionNumber = sectionNum;

	if (sectionNum > lastSectionNum) {
		BP_PRINT( 0, 0,"TABLE_IGNORE :: sectionNum > lastSectionNum ");
		return m_checkVersionResult = TABLE_IGNORE;
	}

	if (m_version == INFINITY) {
		m_version = version;
		m_lastSectionNumber = lastSectionNum;

		if (t_InitSection(sectionNum, lastSectionNum, crc32) == false) {
			BP_PRINT( 0, 0, "TABLE_IGNORE :: t_InitSection is false");
			return m_checkVersionResult = TABLE_IGNORE;
		}
		return m_checkVersionResult = TABLE_INITIAL;
	}

	if ((m_version != version) || (m_lastSectionNumber != lastSectionNum) ||
		((m_version == version) && (t_multiSectionFlag[sectionNum]) && (m_multiSectionCRC[sectionNum] != crc32))) {
		DeleteAll();
		m_version           = version;
		m_lastSectionNumber = lastSectionNum;

		if (t_InitSection(sectionNum, lastSectionNum, crc32) == false) {
			//BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::WARNING,"TABLE_IGNORE :: t_InitSection" );
			return m_checkVersionResult = TABLE_IGNORE;
		}
		//BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::INFO,"TCBaseSection::t_CheckVersion Called[MultiSection, Changed], CRC[%x]", crc32);
		return m_checkVersionResult = TABLE_CHANGE;
	}

	if (t_multiSectionFlag[sectionNum] == true && m_multiSectionCRC[sectionNum] == crc32) {
		return m_checkVersionResult = TABLE_PRESENT;
	}

	t_multiSectionFlag[sectionNum] = true;
	m_multiSectionCRC[sectionNum] = crc32;

	return m_checkVersionResult = TABLE_APPEND;
}

bool TCBaseSection::t_InitSection(int sectionNumber, int lastSectionNumber, uint32_t crc32)
{
	int i;

	if (t_multiSectionFlag) {
		delete[] t_multiSectionFlag;
		t_multiSectionFlag = NULL;
	}

	if (m_multiSectionCRC) {
		delete[] m_multiSectionCRC;
		m_multiSectionCRC = NULL;
	}

    if (m_multiSection) {
        for (i = 0; i < m_multiSectionNumber; i++) {
            if (m_multiSection[i]) {
    	        delete (Section *)m_multiSection[i];
            }
        }
        delete[] m_multiSection;
        m_multiSection = NULL;
    }

	t_multiSectionFlag = new bool[lastSectionNumber + 1];
	m_multiSectionCRC = new uint32_t[lastSectionNumber + 1];
	m_multiSection = new Section *[lastSectionNumber + 1];

#if 0
	//BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::DEBUGGING,"TCBaseSection::t_InitSection Called, CRC[%x]", crc32);
	if (t_multiSectionFlag == NULL)
	{
		BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::MAJOR, "Not enough Memory - t_multiSectionFlag");
		INT_ASSERT(0);
	}

	if (m_multiSectionCRC == NULL)
	{
		BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::MAJOR, "Not enough Memory - t_multiSectionCRC");
		INT_ASSERT(0);
	}

	if (m_multiSection == NULL)
	{
		BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::MAJOR, "Not enough Memory - m_multiSection");
		INT_ASSERT(0);
	}
#endif

    m_multiSectionNumber = lastSectionNumber + 1;

	for (i = 0; i < lastSectionNumber + 1; i++) {
		t_multiSectionFlag[i] = false;
		m_multiSectionCRC[i] = (uint32_t)INFINITY;
		m_multiSection[i] = NULL;
	}

	t_multiSectionFlag[sectionNumber] = true;
	m_multiSectionCRC[sectionNumber] = crc32;

	return true;
}

bool TCBaseSection::t_CheckChangeTable(int version, int sectionNum, int lastSectionNum, uint32_t crc32)
{
	if ((m_version != version) ||
		(m_lastSectionNumber != lastSectionNum) ||
		((m_version == version) && (t_multiSectionFlag[sectionNum]) && (m_multiSectionCRC[sectionNum] != crc32))) {
		return true;
	}

	return false;
}

int TCBaseSection::LastSectionNum(void)
{
	return m_lastSectionNumber;
}

bool TCBaseSection::IsRecvSection(int sectionNumber)
{
	if (t_multiSectionFlag == NULL || sectionNumber > m_lastSectionNumber) {
		return false;
	}

	return t_multiSectionFlag[sectionNumber];
}

bool TCBaseSection::RemoveSection(int sectionNumber)
{
	if (t_multiSectionFlag == NULL || sectionNumber > m_lastSectionNumber) {
		return false;
	}

	t_multiSectionFlag[sectionNumber] = false;

	SetSection(sectionNumber, NULL);
	return true;
}

bool TCBaseSection::SetSection(int sectionNumber, Section *pSection)
{
    if (m_multiSection == NULL || sectionNumber > m_lastSectionNumber) {
        return false;
    }

    if (m_multiSection[sectionNumber] != NULL) {
        delete (Section *)m_multiSection[sectionNumber];
    }

    m_multiSection[sectionNumber] = pSection;
    return true;
}

bool TCBaseSection::GetSection(int sectionNumber, Section **ppSection)
{
    if (m_multiSection == NULL || ppSection == NULL || sectionNumber > m_lastSectionNumber) {
        return false;
    }

    *ppSection = (Section *)m_multiSection[sectionNumber];
    return (*ppSection != NULL);
}

bool TCBaseSection::SaveSection(Section *pSection)
{
    switch (m_checkVersionResult) {
        case TABLE_INITIAL:
        case TABLE_CHANGE:
        case TABLE_APPEND:
            m_checkVersionResult = TABLE_IGNORE; // add once every check
            return SetSection(m_checkSectionNumber, pSection);
        default:
            return false;
    }
}

bool TCBaseSection::IsValid(void)
{
	int i;

	if (t_multiSectionFlag == NULL) {
		BP_PRINT( CCDebugBP::M_DTV, CCDebugBP::MAJOR, "TCBaseSection::IsValid, t_multiSectionFlag is NULL");
		return false;
	}

	for (i = 0; i < m_lastSectionNumber + 1; i++) {
		if (t_multiSectionFlag[i] != true) {
			return false;
		}
	}

	return true;
}

void TCBaseSection::InitSection(void)
{
	int i;

	if (t_multiSectionFlag) {
		delete[] t_multiSectionFlag;
		t_multiSectionFlag = NULL;
	}

	if (m_multiSectionCRC) {
		delete[] m_multiSectionCRC;
		m_multiSectionCRC= NULL;
	}

    if (m_multiSection) {
        for (i = 0; i < m_multiSectionNumber; i++) {
            if (m_multiSection[i])
    	        delete (Section *)m_multiSection[i];
        }
        delete[] m_multiSection;
        m_multiSection = NULL;
    }

	m_version = INFINITY;
	m_lastSectionNumber = 0;
	m_multiSectionNumber = 0;
}



TCBaseSection::TCBaseSection()
{
	t_multiSectionFlag = NULL;
	m_multiSectionCRC = NULL;
	m_multiSection = NULL;
	m_version = INFINITY;
	m_lastSectionNumber = 0;
	m_multiSectionNumber = 0;
    m_checkVersionResult = TABLE_IGNORE;
}

TCBaseSection::~TCBaseSection()
{
	InitSection();
}

