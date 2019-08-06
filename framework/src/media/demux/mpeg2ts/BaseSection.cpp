
#include <debug.h>

#include "Mpeg2TsTypes.h"
#include "Section.h"
#include "BaseSection.h"

BaseSection::BaseSection()
	: m_version((uint8_t)INFINITY)
	, m_lastSectionNumber(0)
	, m_multiSectionCRC(nullptr)
	, m_multiSectionFlag(nullptr)
{
}

BaseSection::~BaseSection()
{
	InitSection();
}

int BaseSection::t_CheckVersion(uint8_t version, uint8_t sectionNum, uint8_t lastSectionNum, uint32_t crc32)
{
	if (sectionNum > lastSectionNum) {
		meddbg("Ignore invalid section! sectionNum > lastSectionNum\n");
		return TABLE_IGNORE;
	}

	if (m_version == (uint8_t)INFINITY) {
		if (!t_InitSection(version, sectionNum, lastSectionNum, crc32)) {
			meddbg("init section failed!\n");
			return TABLE_IGNORE;
		}
		return TABLE_INITIAL;
	}

	// Check if table version changed
	if (t_CheckChangeTable(version, sectionNum, lastSectionNum, crc32)) {
		DeleteAll();
		if (!t_InitSection(version, sectionNum, lastSectionNum, crc32)) {
			meddbg("init section failed!\n");
			return TABLE_IGNORE;
		}

		medwdbg("section change, version %d section %d/%d crc32 0x%x\n", version, sectionNum, lastSectionNum, crc32);
		return TABLE_CHANGE;
	}

	// Check if the section is present
	if (m_multiSectionFlag[sectionNum] && (m_multiSectionCRC[sectionNum] == crc32)) {
		return TABLE_PRESENT;
	}

	// Accept the section
	m_multiSectionFlag[sectionNum] = true;
	m_multiSectionCRC[sectionNum] = crc32;
	return TABLE_APPEND;
}

bool BaseSection::t_InitSection(uint8_t version, uint8_t sectionNumber, uint8_t lastSectionNumber, uint32_t crc32)
{
	int i;

	InitSection();

	m_multiSectionFlag = new bool[lastSectionNumber + 1];
	if (!m_multiSectionFlag) {
		meddbg("Out of memory! lastSectionNumber 0x%x\n", lastSectionNumber);
		return false;
	}

	m_multiSectionCRC = new uint32_t[lastSectionNumber + 1];
	if (!m_multiSectionCRC) {
		meddbg("Out of memory! lastSectionNumber 0x%x\n", lastSectionNumber);
		InitSection();
		return false;
	}

	for (i = 0; i <= lastSectionNumber; i++) {
		m_multiSectionFlag[i] = false;
		m_multiSectionCRC[i] = (uint32_t)INFINITY;
	}

	m_version = version;
	m_lastSectionNumber = lastSectionNumber;

	assert(sectionNumber <= lastSectionNumber);
	m_multiSectionFlag[sectionNumber] = true;
	m_multiSectionCRC[sectionNumber] = crc32;

	return true;
}

bool BaseSection::t_CheckChangeTable(uint8_t version, uint8_t sectionNum, uint8_t lastSectionNum, uint32_t crc32)
{
	assert(m_multiSectionFlag && m_multiSectionCRC);

	if ((m_version != version) ||
		(m_lastSectionNumber != lastSectionNum) ||
		((m_version == version) && (m_multiSectionFlag[sectionNum]) && (m_multiSectionCRC[sectionNum] != crc32))) {
		return true;
	}

	return false;
}

bool BaseSection::IsValid(void)
{
	uint8_t i;

	if (m_multiSectionFlag == nullptr) {
		meddbg("m_multiSectionFlag is nullptr");
		return false;
	}

	for (i = 0; i <= m_lastSectionNumber; i++) {
		if (m_multiSectionFlag[i] != true) {
			return false;
		}
	}

	return true;
}

void BaseSection::InitSection(void)
{
	if (m_multiSectionFlag) {
		delete[] m_multiSectionFlag;
		m_multiSectionFlag = nullptr;
	}

	if (m_multiSectionCRC) {
		delete[] m_multiSectionCRC;
		m_multiSectionCRC= nullptr;
	}

	m_version = (uint8_t)INFINITY;
	m_lastSectionNumber = 0;
}
