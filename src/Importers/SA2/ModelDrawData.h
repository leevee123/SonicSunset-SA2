#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace SA2
{
/* Raw words and physical offsets preserve command fields without assigning unverified material or geometry meanings. */
struct ModelDrawCommand
{
	uint64_t fileOffset;
	uint32_t byteSize;
	uint16_t header;
	std::optional<uint16_t> word02, word04;

	uint8_t opcode() const { return static_cast<uint8_t>(this->header); }
	uint8_t cacheIndex() const { return static_cast<uint8_t>(this->header >> 8); }
	bool isEnd() const { return this->header == 0x00FF; }
	bool definesCache() const { return !this->isEnd() && this->opcode() == 4; }
};

/* A native invocation returns at exact 00FF or command 04; the stored suffix after 04 is not read by this resource. */
struct ModelDrawStream
{
	uint64_t fileOffset, endOffset;
	std::vector<ModelDrawCommand> commands;
	std::vector<uint8_t> data;
};

/* The eight-bit index domain is retained, without claiming a native allocation size; values are caller-supplied buffer offsets. */
using ModelDrawCache = std::array<std::optional<uint64_t>, 256>;

struct ModelDrawTraceStep
{
	ModelDrawCommand command;
	uint32_t callDepth;
};

/* Only stream control is traced. Native state handlers, counters, vertex emitters and graphics effects are not executed. */
struct ModelDrawControlTrace
{
	ModelDrawCache cache;
	std::vector<ModelDrawTraceStep> steps;
};

ModelDrawStream readModelDrawStream(const std::vector<uint8_t>& rBytes_, uint64_t offset_);
ModelDrawControlTrace traceModelDrawControl(const std::vector<uint8_t>& rBytes_, uint64_t offset_, const ModelDrawCache& rCache_, uint64_t maxCommands_, uint32_t maxCallDepth_);
}
