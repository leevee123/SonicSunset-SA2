#include "Importers/SA2/ModelData.h"
#include "BinaryRead.h"
#include <format>
#include <stdexcept>

namespace SA2
{
/* Original node/packet consumers have no file-bound checks; these host guards reject unverified truncated inputs. */
static void requireModelBytes(const std::vector<uint8_t>& rBytes_, uint64_t offset_, uint64_t size_)
{
	if(offset_ > rBytes_.size() || size_ > rBytes_.size() - offset_)
	{
		throw std::runtime_error(std::format("SA2 ModelData: {} bytes at 0x{:X} exceed the buffer.", size_, offset_));
	}
}

/* FUN_8011D554/FUN_801203E0 consume these words, but their complete native node size and live pointer bases remain unknown. */
ModelNodeFields readModelNodeFields(const std::vector<uint8_t>& rBytes_, uint64_t offset_, bool includeField34_)
{
	requireModelBytes(rBytes_, offset_, 0x34);
	ModelNodeFields node;
	node.flags = readBE<uint32_t>(rBytes_, offset_);
	node.payloadPointer = readBE<uint32_t>(rBytes_, offset_ + 4);
	for(uint32_t i = 0; i < 3; i++)
	{
		node.field08Words[i] = readBE<uint32_t>(rBytes_, offset_ + 8 + i * 4);
		node.field14Words[i] = readBE<uint32_t>(rBytes_, offset_ + 0x14 + i * 4);
		node.field20Words[i] = readBE<uint32_t>(rBytes_, offset_ + 0x20 + i * 4);
	}
	node.linkAPointer = readBE<uint32_t>(rBytes_, offset_ + 0x2C);
	node.linkBPointer = readBE<uint32_t>(rBytes_, offset_ + 0x30);
	/* Flag 400 alone does not require +34 in every native path; retain the minimum read unless explicitly requested. */
	if(includeField34_)
	{
		requireModelBytes(rBytes_, offset_, 0x38);
		node.field34Word = readBE<uint32_t>(rBytes_, offset_ + 0x34);
	}
	return node;
}

/* Observed handlers advance records by these byte strides; other original command types are retained without guessed decoding. */
static uint32_t modelRecordStride(uint8_t opcode_)
{
	switch(opcode_)
	{
		case 0x23: return 16;
		case 0x29: return 24;
		case 0x2C: return 28;
		default: return 0;
	}
}

/*
FUN_8011D1D4 tests low-eight-bit FF before reading an info word. Nonterminal headers advance by
4 * ((header >> 16) + 1), independently of the known handler's high16 count/low16 scratch-start word.
The copied reader bounds known records inside the declared packet; original unsafe malformed-input behavior is not emulated.
*/
ModelVertexStream readModelVertexStream(const std::vector<uint8_t>& rBytes_, uint64_t offset_)
{
	ModelVertexStream stream{offset_, offset_, {}, {}};
	uint64_t cursor = offset_;
	while(true)
	{
		requireModelBytes(rBytes_, cursor, 4);
		uint32_t header = readBE<uint32_t>(rBytes_, cursor);
		uint8_t opcode = static_cast<uint8_t>(header);
		ModelVertexPacket packet{cursor, header, 4, 0, std::nullopt};
		if(opcode == 0xFF)
		{
			stream.packets.push_back(packet);
			cursor += 4;
			break;
		}
		packet.byteSize = 4 * ((header >> 16) + 1);
		requireModelBytes(rBytes_, cursor, packet.byteSize);
		/* Every nonterminal reads +4, including unknown opcodes whose four-byte span overlaps the next header. */
		requireModelBytes(rBytes_, cursor + 4, 4);
		packet.infoWord = readBE<uint32_t>(rBytes_, cursor + 4);
		packet.recordStride = modelRecordStride(opcode);
		if(packet.recordStride != 0)
		{
			if(packet.byteSize < 8) throw std::runtime_error("SA2 ModelData: known packet lacks an info word.");
			uint32_t count = *packet.infoWord >> 16;
			if(uint64_t(count) * packet.recordStride > packet.byteSize - 8)
			{
				throw std::runtime_error("SA2 ModelData: known records exceed their packet.");
			}
		}
		stream.packets.push_back(packet);
		cursor += packet.byteSize;
	}
	stream.endOffset = cursor;
	stream.data = {rBytes_.begin() + offset_, rBytes_.begin() + cursor};
	return stream;
}
}
