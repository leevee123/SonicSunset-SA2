#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace GameCube { struct GCDisc; }

namespace SA2
{
/* Callback offsets are relative to a section; section zero suppresses adjustment in FUN_800E839C. */
struct RelEntryPoint
{
	uint8_t section;
	uint32_t offset;
};

/* Stored big-endian fields stay file values, including names/list pointers whose full use is unverified. */
struct RelHeader
{
	uint32_t moduleId, next, previous;
	uint32_t sectionCount, sectionTableOffset;
	uint32_t nameOffset, nameSize, version, bssSize;
	uint32_t relocationOffset, importTableOffset, importTableSize;
	RelEntryPoint prolog, epilog, unresolved;
	uint8_t unknownByte33;
	uint32_t moduleAlignment, bssAlignment;
};

/* Only bit zero is removed from file offsets. An exactly zero stored word with nonzero size is BSS. */
struct RelSection
{
	uint32_t offsetAndFlags, size;

	uint32_t fileOffset() const { return this->offsetAndFlags & ~uint32_t(1); }
	bool isExecutable() const { return (this->offsetAndFlags & 1) != 0; }
	bool isBss() const { return this->offsetAndFlags == 0 && this->size != 0; }
};

struct RelRelocation
{
	uint64_t fileOffset;
	uint16_t delta;
	uint8_t type, section;
	uint32_t addend;
};

/* Target ID alone is not a filename identity. Records include the unchanged END and unknown type values. */
struct RelImport
{
	uint32_t targetModuleId, streamOffset;
	std::vector<RelRelocation> records;
};

/* Decoded bytes retain the stored file; this reader does not allocate BSS or apply imports. */
struct RelModule
{
	RelHeader header;
	std::vector<RelSection> sections;
	std::vector<RelImport> imports;
	std::vector<uint8_t> data;
};

/* GSNE8P revision 0 stored version-2 REL files; raw and PRS disc routes are explicitly separate. */
RelModule readRel(const std::vector<uint8_t>& rBytes_);
RelModule readRelFile(GameCube::GCDisc& rDisc_, const std::string& path_);
RelModule readRelPrsFile(GameCube::GCDisc& rDisc_, const std::string& path_);

/* Addresses describe a caller-selected 32-bit data view, not an executable host mapping or a retail base claim. */
struct RelImageSection
{
	uint32_t address;
	std::vector<uint8_t> data;
};

/* Import indices identify unapplied streams; unknown records retain the original no-write diagnostic cases. */
struct RelocationView
{
	std::vector<RelImageSection> sections;
	std::vector<uint32_t> skippedImportIndices;
	std::vector<RelRelocation> unknownRelocations;
};

/* Apply the first main/self import streams to copied section bytes; foreign streams and original bytes stay intact. */
RelocationView buildRelocationView(const RelModule& rModule_, uint32_t moduleBase_, uint32_t bssBase_);
}
