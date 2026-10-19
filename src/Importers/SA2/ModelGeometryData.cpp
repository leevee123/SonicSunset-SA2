#include "Importers/SA2/ModelGeometryData.h"
#include "BinaryRead.h"
#include <format>
#include <stdexcept>

namespace SA2
{
/* Original geometry helpers dereference native addresses without file or declared-command bounds; copied resources require both. */
static void requireGeometryBytes(uint64_t offset_, uint64_t size_, uint64_t end_)
{
	if(offset_ > end_ || size_ > end_ - offset_)
	{
		throw std::runtime_error(std::format("SA2 ModelGeometryData: {} bytes at 0x{:X} exceed the available span.", size_, offset_));
	}
}

/* D594/D6A4/FEF4 use one index plus skips; D7B4 uses exactly three words; D91C/FFF4 add skips to three. */
static uint32_t geometryRecordWords(uint8_t opcode_, uint16_t info_, ModelGeometryLayout layout_)
{
	uint32_t skips = (info_ >> 14) & 3;
	switch(layout_)
	{
		case ModelGeometryLayout::IndexWithInfoSkips:
			if(opcode_ == 0x40) return 1 + skips;
			break;
		case ModelGeometryLayout::IndexAndPair:
			if(opcode_ == 0x41 || opcode_ == 0x42) return 3;
			break;
		case ModelGeometryLayout::IndexAndPairWithInfoSkips:
			if(opcode_ == 0x41 || opcode_ == 0x42) return 3 + skips;
			break;
	}
	throw std::runtime_error("SA2 ModelGeometryData: unsupported opcode/layout combination.");
}

/*
FUN_8011CCF8 supplies data at +6 and the raw info word to the selected helper. Its unsigned size
sets the outer end independently of the helper's low14 primitive count and signed per-primitive counts.
Zero counts cause native do-while underflow; the host reader rejects them rather than inventing an empty draw.
Multi-stream FUN_80120158 and live state selection are outside this explicit single-stream resource.
*/
ModelGeometryData readModelGeometryData(const std::vector<uint8_t>& rBytes_, uint64_t offset_, ModelGeometryLayout layout_)
{
	requireGeometryBytes(offset_, 6, rBytes_.size());
	uint16_t header = readBE<uint16_t>(rBytes_, offset_);
	uint16_t size = readBE<uint16_t>(rBytes_, offset_ + 2);
	uint16_t info = readBE<uint16_t>(rBytes_, offset_ + 4);
	uint32_t recordWords = geometryRecordWords(static_cast<uint8_t>(header), info, layout_);
	uint64_t byteSize = 4 + 2 * uint64_t(size);
	requireGeometryBytes(offset_, byteSize, rBytes_.size());
	if(byteSize < 6) throw std::runtime_error("SA2 ModelGeometryData: info word lies outside the declared command.");
	uint32_t primitiveCount = info & 0x3FFF;
	if(primitiveCount == 0) throw std::runtime_error("SA2 ModelGeometryData: zero primitive count has no bounded native iteration.");
	uint64_t cursor = offset_ + 6;
	ModelGeometryData geometry{offset_, cursor, offset_ + byteSize, header, info, recordWords, layout_, {}, {}};
	for(uint32_t i = 0; i < primitiveCount; i++)
	{
		requireGeometryBytes(cursor, 2, geometry.endOffset);
		uint16_t countWord = readBE<uint16_t>(rBytes_, cursor);
		int32_t signedCount = countWord < 0x8000 ? int32_t(countWord) : int32_t(countWord) - 0x10000;
		uint32_t count = static_cast<uint32_t>(signedCount < 0 ? -signedCount : signedCount);
		if(count == 0) throw std::runtime_error("SA2 ModelGeometryData: zero record count has no bounded native iteration.");
		ModelGeometryPrimitive primitive{cursor, countWord, {}};
		cursor += 2;
		requireGeometryBytes(cursor, uint64_t(count) * recordWords * 2, geometry.endOffset);
		for(uint32_t j = 0; j < count; j++)
		{
			ModelGeometryRecord record{cursor, readBE<uint16_t>(rBytes_, cursor), {}};
			for(uint32_t k = 1; k < recordWords; k++) record.followingWords.push_back(readBE<uint16_t>(rBytes_, cursor + k * 2));
			primitive.records.push_back(record);
			cursor += recordWords * 2;
		}
		geometry.primitives.push_back(primitive);
	}
	geometry.recordsEndOffset = cursor;
	geometry.data = {rBytes_.begin() + offset_, rBytes_.begin() + geometry.endOffset};
	return geometry;
}
}
