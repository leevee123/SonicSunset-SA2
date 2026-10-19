#include "Importers/SA2/ModelGeometryGroup.h"
#include "BinaryRead.h"
#include <format>
#include <stdexcept>

namespace SA2
{
/* Native FUN_80120158 has no file/declared-span checks. This copied-data path keeps each stream inside both host boundaries. */
static void requireGroupBytes(uint64_t offset_, uint64_t size_, uint64_t end_)
{
	if(offset_ > end_ || size_ > end_ - offset_)
	{
		throw std::runtime_error(std::format("SA2 ModelGeometryGroup: {} bytes at 0x{:X} exceed the available span.", size_, offset_));
	}
}

/*
FUN_8011CCF8 collects any nonterminal high-family command, then reaches FUN_80120158 through a completing 41/42 path.
The caller supplies that collection explicitly: no first-info group-size guess or native array-capacity claim is made.
FUN_80120158 receives the completing command's info, while each primitive's signed record count comes from stream zero.
The host limit of eight streams keeps the collector's type/pointer storage separate; the native code has no such guard.
*/
ModelGeometryGroup readModelGeometryGroup(const std::vector<uint8_t>& rBytes_, const std::vector<uint64_t>& rCommandOffsets_)
{
	if(rCommandOffsets_.empty() || rCommandOffsets_.size() > 8)
	{
		throw std::runtime_error("SA2 ModelGeometryGroup: unsupported caller stream count.");
	}
	ModelGeometryGroup group{0, {}, {}};
	std::vector<uint64_t> cursors;
	for(uint64_t offset : rCommandOffsets_)
	{
		requireGroupBytes(offset, 6, rBytes_.size());
		uint16_t header = readBE<uint16_t>(rBytes_, offset);
		if(header == 0xFF || static_cast<uint8_t>(header) < 0x40)
		{
			throw std::runtime_error("SA2 ModelGeometryGroup: stream is not an outer geometry-family command.");
		}
		uint16_t size = readBE<uint16_t>(rBytes_, offset + 2);
		uint16_t info = readBE<uint16_t>(rBytes_, offset + 4);
		uint64_t byteSize = 4 + 2 * uint64_t(size);
		requireGroupBytes(offset, byteSize, rBytes_.size());
		if(byteSize < 6) throw std::runtime_error("SA2 ModelGeometryGroup: info lies outside the declared command.");
		group.streams.push_back({offset, offset + 6, offset + byteSize, header, info, {}});
		cursors.push_back(offset + 6);
	}
	uint8_t finalOpcode = static_cast<uint8_t>(group.streams.back().header);
	if(finalOpcode != 0x41 && finalOpcode != 0x42) throw std::runtime_error("SA2 ModelGeometryGroup: completing opcode has no grouped helper path.");
	group.infoWord = group.streams.back().infoWord;
	uint32_t primitiveCount = group.infoWord & 0x3FFF;
	if(primitiveCount == 0) throw std::runtime_error("SA2 ModelGeometryGroup: zero primitive count has no bounded native iteration.");
	for(uint32_t i = 0; i < primitiveCount; i++)
	{
		ModelGeometryGroupPrimitive primitive;
		/* The native primary cursor advances before its load; secondary prefix words are skipped, retained here only as raw metadata. */
		for(size_t stream = 0; stream < group.streams.size(); stream++)
		{
			requireGroupBytes(cursors[stream], 2, group.streams[stream].endOffset);
			uint64_t prefixOffset = cursors[stream];
			cursors[stream] += 2;
			primitive.prefixes.push_back({prefixOffset, readBE<uint16_t>(rBytes_, prefixOffset)});
		}
		uint16_t countWord = primitive.prefixes[0].word;
		int32_t signedCount = countWord < 0x8000 ? int32_t(countWord) : int32_t(countWord) - 0x10000;
		uint32_t count = static_cast<uint32_t>(signedCount < 0 ? -signedCount : signedCount);
		if(count == 0) throw std::runtime_error("SA2 ModelGeometryGroup: zero record count has no bounded native iteration.");
		for(size_t stream = 0; stream < group.streams.size(); stream++)
		{
			requireGroupBytes(cursors[stream], uint64_t(count) * 6, group.streams[stream].endOffset);
		}
		for(uint32_t j = 0; j < count; j++)
		{
			ModelGeometryGroupRecord record;
			/* All streams advance three halfwords per record; only stream zero's first word is loaded for scratch by the native helper. */
			for(size_t stream = 0; stream < group.streams.size(); stream++)
			{
				uint64_t recordOffset = cursors[stream];
				cursors[stream] += 2;
				uint16_t first = readBE<uint16_t>(rBytes_, recordOffset);
				uint64_t pairOffset = cursors[stream];
				cursors[stream] += 2;
				uint16_t pairFirst = readBE<uint16_t>(rBytes_, pairOffset);
				pairOffset = cursors[stream];
				cursors[stream] += 2;
				uint16_t pairSecond = readBE<uint16_t>(rBytes_, pairOffset);
				record.streams.push_back({recordOffset, first, {pairFirst, pairSecond}});
			}
			primitive.records.push_back(record);
		}
		group.primitives.push_back(primitive);
	}
	/* Native pointer-array/data and stack-array aliases are outside this owned-cursor resource; equal immutable stream spans remain supported. */
	for(size_t stream = 0; stream < group.streams.size(); stream++)
	{
		auto& result = group.streams[stream];
		result.recordsEndOffset = cursors[stream];
		result.data = {rBytes_.begin() + result.fileOffset, rBytes_.begin() + result.endOffset};
	}
	return group;
}
}
