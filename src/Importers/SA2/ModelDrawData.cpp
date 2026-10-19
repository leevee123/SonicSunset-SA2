#include "Importers/SA2/ModelDrawData.h"
#include "BinaryRead.h"
#include <format>
#include <stdexcept>

namespace SA2
{
/* Original FUN_8011CCF8 uses native addresses without file bounds; the copied reader rejects unavailable host bytes. */
static void requireModelDrawBytes(const std::vector<uint8_t>& rBytes_, uint64_t offset_, uint64_t size_)
{
	if(offset_ > rBytes_.size() || size_ > rBytes_.size() - offset_)
	{
		throw std::runtime_error(std::format("SA2 ModelDrawData: {} bytes at 0x{:X} exceed the buffer.", size_, offset_));
	}
}

/*
FUN_8011CCF8 tests the complete halfword for 00FF. Low-byte 00..07 controls occupy one halfword,
08..0F two, 10..3F advance by 2 * (signed size + 2), and 40..FF by 2 * (unsigned size + 2).
The last family always reads +4, even when size zero makes that word overlap the next command.
Negative signed sizes are rejected as a host policy rather than following native backward addresses.
*/
static ModelDrawCommand readModelDrawCommand(const std::vector<uint8_t>& rBytes_, uint64_t offset_)
{
	requireModelDrawBytes(rBytes_, offset_, 2);
	ModelDrawCommand command{offset_, 2, readBE<uint16_t>(rBytes_, offset_), std::nullopt, std::nullopt};
	if(command.isEnd() || command.opcode() < 8) return command;
	requireModelDrawBytes(rBytes_, offset_ + 2, 2);
	command.word02 = readBE<uint16_t>(rBytes_, offset_ + 2);
	command.byteSize = 4;
	if(command.opcode() < 0x10) return command;
	uint32_t size = *command.word02;
	if(command.opcode() < 0x40)
	{
		if((size & 0x8000) != 0) throw std::runtime_error("SA2 ModelDrawData: negative state-command size is unsupported.");
	}
	else
	{
		requireModelDrawBytes(rBytes_, offset_ + 4, 2);
		command.word04 = readBE<uint16_t>(rBytes_, offset_ + 4);
	}
	command.byteSize = 2 * (size + 2);
	requireModelDrawBytes(rBytes_, offset_, command.byteSize);
	return command;
}

/* Cache calls remain raw commands here; command 04 returns before its saved suffix, as the original routine does. */
ModelDrawStream readModelDrawStream(const std::vector<uint8_t>& rBytes_, uint64_t offset_)
{
	ModelDrawStream stream{offset_, offset_, {}, {}};
	uint64_t cursor = offset_;
	while(true)
	{
		ModelDrawCommand command = readModelDrawCommand(rBytes_, cursor);
		stream.commands.push_back(command);
		cursor += command.byteSize;
		if(command.isEnd() || command.definesCache()) break;
	}
	stream.endOffset = cursor;
	stream.data = {rBytes_.begin() + offset_, rBytes_.begin() + cursor};
	return stream;
}

/*
The explicit stack reproduces command 05 call/resume and command 04 store/return without executing graphics.
Initial cache contents and command/depth limits are explicit caller inputs; missing entries or exhausted limits
are host errors. A copied cache leaves caller state unchanged on failure and supports offset zero as a value.
*/
ModelDrawControlTrace traceModelDrawControl(const std::vector<uint8_t>& rBytes_, uint64_t offset_, const ModelDrawCache& rCache_, uint64_t maxCommands_, uint32_t maxCallDepth_)
{
	if(maxCommands_ == 0 || maxCallDepth_ == 0) throw std::runtime_error("SA2 ModelDrawData: trace limits must be positive.");
	ModelDrawControlTrace trace{rCache_, {}};
	std::vector<uint64_t> frames{offset_};
	while(!frames.empty())
	{
		if(trace.steps.size() >= maxCommands_) throw std::runtime_error("SA2 ModelDrawData: command limit exceeded.");
		ModelDrawCommand command = readModelDrawCommand(rBytes_, frames.back());
		uint64_t next = command.fileOffset + command.byteSize;
		trace.steps.push_back({command, static_cast<uint32_t>(frames.size() - 1)});
		frames.back() = next;
		if(command.isEnd())
		{
			frames.pop_back();
		}
		else if(command.definesCache())
		{
			trace.cache[command.cacheIndex()] = next;
			frames.pop_back();
		}
		else if(command.opcode() == 5)
		{
			const auto& target = trace.cache[command.cacheIndex()];
			if(!target) throw std::runtime_error("SA2 ModelDrawData: cache reference has no caller-supplied target.");
			if(frames.size() >= maxCallDepth_) throw std::runtime_error("SA2 ModelDrawData: call depth limit exceeded.");
			frames.push_back(*target);
		}
	}
	return trace;
}
}
