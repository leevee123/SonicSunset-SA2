#pragma once
#include <array>
#include <cstdint>
#include <vector>

namespace SA2
{
/* Each stream retains its own declared bytes and final copied cursor; overlapping byte spans do not alias cursor slots. */
struct ModelGeometryGroupStream
{
	uint64_t fileOffset, recordsEndOffset, endOffset;
	uint16_t header, infoWord;
	std::vector<uint8_t> data;
};

struct ModelGeometryGroupPrefix
{
	uint64_t fileOffset;
	uint16_t word;
};

/* The first stream's first word is a signed scratch index; other streams skip that word. All pair words remain raw. */
struct ModelGeometryGroupRecordStream
{
	uint64_t fileOffset;
	uint16_t firstWord;
	std::array<uint16_t, 2> pairWords;
};

struct ModelGeometryGroupRecord
{
	std::vector<ModelGeometryGroupRecordStream> streams;
};

/* Only prefixes[0] determines the record count; secondary prefixes are preserved without comparison or interpretation. */
struct ModelGeometryGroupPrimitive
{
	std::vector<ModelGeometryGroupPrefix> prefixes;
	std::vector<ModelGeometryGroupRecord> records;
};

/* Ordered command offsets are explicit caller input; this resource does not select native groups or execute draw state. */
struct ModelGeometryGroup
{
	uint16_t infoWord;
	std::vector<ModelGeometryGroupStream> streams;
	std::vector<ModelGeometryGroupPrimitive> primitives;
};

ModelGeometryGroup readModelGeometryGroup(const std::vector<uint8_t>& rBytes_, const std::vector<uint64_t>& rCommandOffsets_);
}
