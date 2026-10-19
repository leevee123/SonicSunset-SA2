#include "Importers/SA2/PointerBank.h"
#include "Importers/SA2/Prs.h"
#include "BinaryRead.h"
#include <format>
#include <stdexcept>
#include <unordered_set>

namespace SA2
{
/* Bounds/cycle failures are host safeguards; FUN_80050210/FUN_8002F88C do not validate original file spans. */
static void requireBankBytes(const std::vector<uint8_t>& rBytes_, uint64_t offset_, uint64_t size_)
{
	if(offset_ > rBytes_.size() || size_ > rBytes_.size() - offset_)
	{
		throw std::runtime_error(std::format("SA2 PointerBank: {} bytes at 0x{:X} exceed the buffer.", size_, offset_));
	}
}

/* Preserve every decoded byte; the sentinel requires only its ID word, and zero/out-of-range IDs are not filtered. */
PointerBank readPointerBank(const std::vector<uint8_t>& rBytes_)
{
	PointerBank bank;
	uint64_t cursor = 0;
	while(true)
	{
		requireBankBytes(rBytes_, cursor, 4);
		int32_t id = readBE<int32_t>(rBytes_, cursor);
		if(id == -1) { bank.sentinelOffset = cursor; break; }
		requireBankBytes(rBytes_, cursor, 8);
		bank.entries.push_back({cursor, id, readBE<uint32_t>(rBytes_, cursor + 4)});
		cursor += 8;
	}
	bank.data = rBytes_;
	return bank;
}

PointerBank readPointerBankPrsFile(GameCube::GCDisc& rDisc_, const std::string& path_)
{
	return readPointerBank(readPrsFile(rDisc_, path_));
}

/* Byte-order stores also record unchanged-value writes; payload additions wrap exactly as 32-bit original arithmetic. */
static void storeBankWord(PointerBankView& rView_, uint32_t offset_, uint32_t value_)
{
	requireBankBytes(rView_.data, offset_, 4);
	uint32_t before = readBE<uint32_t>(rView_.data, offset_);
	for(uint32_t i = 0; i < 4; i++) rView_.data[offset_ + i] = static_cast<uint8_t>(value_ >> (8 * (3 - i)));
	rView_.stores.push_back({offset_, before, value_});
}

static uint32_t bankOffset(const PointerBankView& rView_, uint32_t pointer_, uint32_t base_, uint32_t size_)
{
	if(pointer_ < base_) throw std::runtime_error("SA2 PointerBank: pointer is outside the declared view.");
	uint32_t offset = pointer_ - base_;
	requireBankBytes(rView_.data, offset, size_);
	return offset;
}

/* Low positive pointer words gain the base; zero and bit31-set words are kept exactly as FUN_8002F88C does. */
static uint32_t adjustBankPointer(PointerBankView& rView_, uint32_t offset_, uint32_t pointer_, uint32_t base_)
{
	if(pointer_ != 0 && (pointer_ & 0x80000000) == 0)
	{
		pointer_ += base_;
		storeBankWord(rView_, offset_, pointer_);
	}
	return pointer_;
}

struct BankTraversalFrame
{
	uint32_t offset, linkB;
	uint8_t phase;
};

/*
FUN_8002F88C saves +4/+2C/+30 before any write, adjusts the opaque target's two words without inner bit31 tests,
then converts/traverses link A before converting the saved link B. Explicit frames preserve that recursive order
without using host recursion. Active-path cycle checks do not prune repeated nodes on separate paths.
*/
static void visitBankNode(PointerBankView& rView_, uint32_t pointer_, uint32_t base_)
{
	std::vector<BankTraversalFrame> stack{{bankOffset(rView_, pointer_, base_, 0x34), 0, 0}};
	std::unordered_set<uint32_t> active;
	while(!stack.empty())
	{
		auto& frame = stack.back();
		if(frame.phase == 0)
		{
			if(!active.insert(frame.offset).second) throw std::runtime_error("SA2 PointerBank: cyclic node links are unverified.");
			rView_.nodeVisits.push_back(frame.offset);
			uint32_t payload = readBE<uint32_t>(rView_.data, frame.offset + 4);
			uint32_t linkA = readBE<uint32_t>(rView_.data, frame.offset + 0x2C);
			frame.linkB = readBE<uint32_t>(rView_.data, frame.offset + 0x30);
			if(payload != 0 && (payload & 0x80000000) == 0)
			{
				payload = adjustBankPointer(rView_, frame.offset + 4, payload, base_);
				uint32_t target = bankOffset(rView_, payload, base_, 8);
				rView_.payloadVisits.push_back(target);
				for(uint32_t i = 0; i < 2; i++)
				{
					uint32_t offset = target + i * 4;
					uint32_t value = readBE<uint32_t>(rView_.data, offset);
					if(value != 0) storeBankWord(rView_, offset, value + base_);
				}
			}
			frame.phase = 1;
			linkA = adjustBankPointer(rView_, frame.offset + 0x2C, linkA, base_);
			if(linkA != 0) stack.push_back({bankOffset(rView_, linkA, base_, 0x34), 0, 0});
		}
		else if(frame.phase == 1)
		{
			frame.phase = 2;
			uint32_t linkB = adjustBankPointer(rView_, frame.offset + 0x30, frame.linkB, base_);
			if(linkB != 0) stack.push_back({bankOffset(rView_, linkB, base_, 0x34), 0, 0});
		}
		else
		{
			active.erase(frame.offset);
			stack.pop_back();
		}
	}
}

/* Root traversal ignores registry eligibility and rescans mutable IDs; aliased node writes can change later termination. */
PointerBankView buildPointerBankView(const PointerBank& rBank_, uint32_t base_)
{
	if((base_ & 0x80000000) == 0 || uint64_t(base_) + rBank_.data.size() > 0x100000000ULL)
	{
		throw std::runtime_error("SA2 PointerBank: unverified view address range.");
	}
	PointerBankView view;
	view.data = rBank_.data;
	uint64_t cursor = 0;
	while(true)
	{
		requireBankBytes(view.data, cursor, 4);
		if(readBE<int32_t>(view.data, cursor) == -1) break;
		requireBankBytes(view.data, cursor, 8);
		uint32_t offset = static_cast<uint32_t>(cursor + 4);
		uint32_t pointer = readBE<uint32_t>(view.data, offset);
		pointer = adjustBankPointer(view, offset, pointer, base_);
		if(pointer != 0) visitBankNode(view, pointer, base_);
		cursor += 8;
	}
	return view;
}
}
