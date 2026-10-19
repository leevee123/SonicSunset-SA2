#include "Importers/SA2/Rel.h"
#include "Importers/SA2/Prs.h"
#include "BinaryRead.h"
#include "GCDisc.h"
#include <algorithm>
#include <format>
#include <stdexcept>
#include <utility>

namespace SA2
{
/* Host checks protect table/stream reads; the original linker has no corresponding input bounds checks. */
static void requireBytes(const std::vector<uint8_t>& rBytes_, uint64_t offset_, uint64_t size_)
{
	if(offset_ > rBytes_.size() || size_ > rBytes_.size() - offset_)
	{
		throw std::runtime_error(std::format("SA2 Rel: {} bytes at 0x{:X} exceed the buffer.", size_, offset_));
	}
}

/* FUN_800E839C reads these stored fields before converting offsets into pointers; only version 2 is validated. */
static RelHeader readHeader(const std::vector<uint8_t>& rBytes_)
{
	requireBytes(rBytes_, 0, 0x48);
	RelHeader header;
	header.moduleId = readBE<uint32_t>(rBytes_, 0x00);
	header.next = readBE<uint32_t>(rBytes_, 0x04);
	header.previous = readBE<uint32_t>(rBytes_, 0x08);
	header.sectionCount = readBE<uint32_t>(rBytes_, 0x0C);
	header.sectionTableOffset = readBE<uint32_t>(rBytes_, 0x10);
	header.nameOffset = readBE<uint32_t>(rBytes_, 0x14);
	header.nameSize = readBE<uint32_t>(rBytes_, 0x18);
	header.version = readBE<uint32_t>(rBytes_, 0x1C);
	if(header.version != 2) throw std::runtime_error("SA2 Rel: unverified module version.");
	header.bssSize = readBE<uint32_t>(rBytes_, 0x20);
	header.relocationOffset = readBE<uint32_t>(rBytes_, 0x24);
	header.importTableOffset = readBE<uint32_t>(rBytes_, 0x28);
	header.importTableSize = readBE<uint32_t>(rBytes_, 0x2C);
	header.prolog = {rBytes_[0x30], readBE<uint32_t>(rBytes_, 0x34)};
	header.epilog = {rBytes_[0x31], readBE<uint32_t>(rBytes_, 0x38)};
	header.unresolved = {rBytes_[0x32], readBE<uint32_t>(rBytes_, 0x3C)};
	header.unknownByte33 = rBytes_[0x33];
	header.moduleAlignment = readBE<uint32_t>(rBytes_, 0x40);
	header.bssAlignment = readBE<uint32_t>(rBytes_, 0x44);
	return header;
}

/* FUN_800E8128 consumes eight-byte records through type 203. Preserve all fields instead of binding target IDs. */
static RelImport readImport(const std::vector<uint8_t>& rBytes_, uint64_t offset_)
{
	RelImport entry;
	entry.targetModuleId = readBE<uint32_t>(rBytes_, offset_);
	entry.streamOffset = readBE<uint32_t>(rBytes_, offset_ + 4);
	uint64_t cursor = entry.streamOffset;
	while(true)
	{
		requireBytes(rBytes_, cursor, 8);
		RelRelocation record{cursor, readBE<uint16_t>(rBytes_, cursor), rBytes_[cursor + 2],
			rBytes_[cursor + 3], readBE<uint32_t>(rBytes_, cursor + 4)};
		entry.records.push_back(record);
		cursor += 8;
		if(record.type == 203) break;
	}
	return entry;
}

/* The section table distinguishes file payload from BSS; empty sections and opaque header values remain intact. */
RelModule readRel(const std::vector<uint8_t>& rBytes_)
{
	RelModule module;
	module.header = readHeader(rBytes_);
	const RelHeader& header = module.header;
	if(header.sectionCount != 0) requireBytes(rBytes_, header.sectionTableOffset, uint64_t(header.sectionCount) * 8);
	module.sections.reserve(header.sectionCount);
	for(uint32_t i = 0; i < header.sectionCount; i++)
	{
		uint64_t offset = uint64_t(header.sectionTableOffset) + uint64_t(i) * 8;
		RelSection section{readBE<uint32_t>(rBytes_, offset), readBE<uint32_t>(rBytes_, offset + 4)};
		if(section.offsetAndFlags != 0 && section.size != 0) requireBytes(rBytes_, section.fileOffset(), section.size);
		module.sections.push_back(section);
	}

	/* Original import traversal uses eight-byte entries; a partial host entry is rejected before reading. */
	if(header.importTableSize % 8 != 0) throw std::runtime_error("SA2 Rel: partial import-table entry.");
	if(header.importTableSize != 0) requireBytes(rBytes_, header.importTableOffset, header.importTableSize);
	module.imports.reserve(header.importTableSize / 8);
	for(uint64_t offset = 0; offset < header.importTableSize; offset += 8)
	{
		module.imports.push_back(readImport(rBytes_, uint64_t(header.importTableOffset) + offset));
	}
	module.data = rBytes_;
	return module;
}

RelModule readRelFile(GameCube::GCDisc& rDisc_, const std::string& path_)
{
	return readRel(rDisc_.readFile(path_));
}

RelModule readRelPrsFile(GameCube::GCDisc& rDisc_, const std::string& path_)
{
	return readRel(readPrsFile(rDisc_, path_));
}

/* Host view ranges must be unambiguous and fit 32-bit addresses; this does not execute the original cache operations. */
static void checkViewRanges(const std::vector<RelImageSection>& rSections_)
{
	std::vector<std::pair<uint64_t, uint64_t>> ranges;
	for(const auto& section : rSections_)
	{
		if(section.data.empty()) continue;
		uint64_t end = uint64_t(section.address) + section.data.size();
		if(end > 0x100000000ULL) throw std::runtime_error("SA2 Rel: view section exceeds 32-bit addresses.");
		ranges.push_back({section.address, end});
	}
	std::sort(ranges.begin(), ranges.end());
	for(size_t i = 1; i < ranges.size(); i++)
	{
		if(ranges[i].first < ranges[i - 1].second) throw std::runtime_error("SA2 Rel: view sections overlap.");
	}
}

/* FUN_800E8128 selects the first matching import ID; later duplicate entries are not traversed by that invocation. */
static size_t findImport(const RelModule& rModule_, uint32_t targetId_)
{
	for(size_t i = 0; i < rModule_.imports.size(); i++)
	{
		if(rModule_.imports[i].targetModuleId == targetId_) return i;
	}
	return rModule_.imports.size();
}

/* Store two/four bytes in original big-endian order; narrowing deliberately keeps only the selected low bits. */
static void writeRelocation(std::vector<uint8_t>& rBytes_, uint64_t offset_, uint32_t value_, uint32_t size_)
{
	requireBytes(rBytes_, offset_, size_);
	for(uint32_t i = 0; i < size_; i++)
	{
		rBytes_[offset_ + i] = static_cast<uint8_t>(value_ >> (8 * (size_ - i - 1)));
	}
}

/*
FUN_800E8128 checks END before delta, resets the cursor at SECTION, and masks/truncates without checking branch reach.
This data view requires the observed initial SECTION and bounds its writes; unknown types advance without writing.
*/
static void applyImport(const RelModule& rModule_, RelocationView& rView_, size_t importIndex_)
{
	const auto& entry = rModule_.imports[importIndex_];
	if(entry.records.empty() || entry.records.front().type != 202)
	{
		throw std::runtime_error("SA2 Rel: unverified relocation stream without initial SECTION.");
	}
	uint32_t cursor = 0;
	uint8_t destination = 0;
	bool ended = false;
	for(const auto& record : entry.records)
	{
		if(record.type == 203) { ended = true; break; }
		cursor += record.delta;
		if(record.type == 202)
		{
			if(record.section >= rView_.sections.size()) throw std::runtime_error("SA2 Rel: invalid destination section.");
			destination = record.section;
			cursor = rView_.sections[destination].address;
			continue;
		}
		if(record.type == 0 || record.type == 201) continue;
		if(record.type != 1 && record.type != 2 && record.type != 3 && record.type != 4 &&
			record.type != 5 && record.type != 6 && record.type != 10)
		{
			rView_.unknownRelocations.push_back(record);
			continue;
		}

		/* ID zero uses an absolute addend; self imports add the selected source section address modulo 2^32. */
		uint32_t target = record.addend;
		if(entry.targetModuleId != 0)
		{
			if(record.section >= rView_.sections.size()) throw std::runtime_error("SA2 Rel: invalid source section.");
			target += rView_.sections[record.section].address & ~uint32_t(1);
		}
		auto& section = rView_.sections[destination];
		uint32_t offset = cursor - section.address;
		uint32_t size = (record.type == 1 || record.type == 2 || record.type == 10) ? 4 : 2;
		requireBytes(section.data, offset, size);
		uint32_t value = target;
		if(record.type == 2 || record.type == 10)
		{
			uint32_t old = readBE<uint32_t>(section.data, offset);
			value = ((record.type == 10 ? target - cursor : target) & 0x03FFFFFC) | (old & 0xFC000003);
		}
		else if(record.type == 5) value = target >> 16;
		else if(record.type == 6) value = (target >> 16) + ((target & 0x8000) != 0);
		writeRelocation(section.data, offset, value, size);
	}
	if(!ended) throw std::runtime_error("SA2 Rel: relocation view stream has no END.");
}

/*
FUN_800E839C checks required alignment with division, zeros BSS, and assigns its sections consecutively without padding.
The copied section view omits header/list/callback mutation and native execution; odd, overlapping or inconsistent spans
are rejected as unvalidated host inputs. The raw metadata reader continues to retain those values.
*/
RelocationView buildRelocationView(const RelModule& rModule_, uint32_t moduleBase_, uint32_t bssBase_)
{
	const auto& header = rModule_.header;
	if(header.version != 2 || header.sectionCount != rModule_.sections.size())
	{
		throw std::runtime_error("SA2 Rel: inconsistent or unverified view metadata.");
	}
	if((moduleBase_ & 1) || (header.bssSize != 0 && (bssBase_ & 1)) ||
		(header.moduleAlignment != 0 && moduleBase_ % header.moduleAlignment != 0) ||
		(header.bssAlignment != 0 && bssBase_ % header.bssAlignment != 0))
	{
		throw std::runtime_error("SA2 Rel: view base does not meet supported alignment.");
	}
	uint64_t bssSize = 0;
	for(const auto& section : rModule_.sections) if(section.isBss()) bssSize += section.size;
	if(bssSize != header.bssSize) throw std::runtime_error("SA2 Rel: view BSS total differs from the header.");
	RelocationView view;
	view.sections.reserve(rModule_.sections.size());
	uint64_t bssCursor = bssBase_;
	for(const auto& source : rModule_.sections)
	{
		RelImageSection section{0, {}};
		if(source.isBss())
		{
			if((bssCursor & 1) || bssCursor + source.size > 0x100000000ULL)
			{
				throw std::runtime_error("SA2 Rel: unverified BSS section range.");
			}
			section.address = static_cast<uint32_t>(bssCursor);
			section.data.resize(source.size, 0);
			bssCursor += source.size;
		}
		else if(source.offsetAndFlags != 0)
		{
			uint64_t address = uint64_t(moduleBase_) + source.fileOffset();
			if(address + source.size > 0x100000000ULL) throw std::runtime_error("SA2 Rel: unverified initialized section range.");
			section.address = static_cast<uint32_t>(address);
			requireBytes(rModule_.data, source.fileOffset(), source.size);
			uint64_t end = uint64_t(source.fileOffset()) + source.size;
			section.data = {rModule_.data.begin() + source.fileOffset(), rModule_.data.begin() + end};
		}
		view.sections.push_back(std::move(section));
	}
	checkViewRanges(view.sections);

	/* The initial linker pass applies ID zero first, then the supplied module's own ID; foreign bindings stay unknown. */
	size_t mainImport = findImport(rModule_, 0);
	size_t selfImport = findImport(rModule_, header.moduleId);
	if(mainImport != rModule_.imports.size()) applyImport(rModule_, view, mainImport);
	if(selfImport != rModule_.imports.size()) applyImport(rModule_, view, selfImport);
	for(size_t i = 0; i < rModule_.imports.size(); i++)
	{
		if(i != mainImport && i != selfImport) view.skippedImportIndices.push_back(static_cast<uint32_t>(i));
	}
	return view;
}
}
