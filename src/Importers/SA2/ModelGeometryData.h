#pragma once
#include <cstdint>
#include <vector>

namespace SA2
{
/* Native helper selection depends on live draw state; the caller names the proven single-stream layout explicitly. */
enum class ModelGeometryLayout : uint8_t
{
	IndexWithInfoSkips,
	IndexAndPair,
	IndexAndPairWithInfoSkips
};

/* The first word is used as a signed scratch index by the original; all following attribute or skipped words retain their bits. */
struct ModelGeometryRecord
{
	uint64_t fileOffset;
	uint16_t indexWord;
	std::vector<uint16_t> followingWords;
};

/* Negative native counts are made positive for iteration; the raw sign is kept without assigning winding or topology meaning. */
struct ModelGeometryPrimitive
{
	uint64_t fileOffset;
	uint16_t countWord;
	std::vector<ModelGeometryRecord> records;
};

/* Declared bytes include any unconsumed tail; recordsEndOffset distinguishes helper consumption from outer command movement. */
struct ModelGeometryData
{
	uint64_t fileOffset, recordsEndOffset, endOffset;
	uint16_t header, infoWord;
	uint32_t recordWordCount;
	ModelGeometryLayout layout;
	std::vector<ModelGeometryPrimitive> primitives;
	std::vector<uint8_t> data;
};

ModelGeometryData readModelGeometryData(const std::vector<uint8_t>& rBytes_, uint64_t offset_, ModelGeometryLayout layout_);
}
