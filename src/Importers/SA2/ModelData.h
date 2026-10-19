#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace SA2
{
/* Node consumers use mode-dependent scalar fields; raw words retain signed zero, NaNs and low-bit angle indexing. */
struct ModelNodeFields
{
	uint32_t flags, payloadPointer;
	std::array<uint32_t, 3> field08Words, field14Words, field20Words;
	uint32_t linkAPointer, linkBPointer;
	std::optional<uint32_t> field34Word;
};

/* Physical offsets and raw headers remain canonical file values; unsupported packet records are kept opaque. */
struct ModelVertexPacket
{
	uint64_t fileOffset;
	uint32_t header, byteSize, recordStride;
	std::optional<uint32_t> infoWord;

	uint8_t opcode() const { return static_cast<uint8_t>(this->header); }
	bool isEnd() const { return this->opcode() == 0xFF; }
};

/* The raw stream includes END and any packet padding; no vertex transform, weight conversion or GPU state is applied. */
struct ModelVertexStream
{
	uint64_t fileOffset, endOffset;
	std::vector<ModelVertexPacket> packets;
	std::vector<uint8_t> data;
};

/* Native +34 reads depend on the consumer/provider path; the caller explicitly requests that optional word. */
ModelNodeFields readModelNodeFields(const std::vector<uint8_t>& rBytes_, uint64_t offset_, bool includeField34_ = false);
ModelVertexStream readModelVertexStream(const std::vector<uint8_t>& rBytes_, uint64_t offset_);
}
