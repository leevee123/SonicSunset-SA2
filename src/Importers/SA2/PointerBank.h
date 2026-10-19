#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace GameCube { struct GCDisc; }

namespace SA2
{
/* FUN_80050210 stops on signed ID -1 before reading its following word; other records retain raw pointers. */
struct PointerBankEntry
{
	uint64_t fileOffset;
	int32_t id;
	uint32_t pointer;

	bool isRegistryEligible() const { return this->id >= 0 && this->id < 0x214; }
};

struct PointerBank
{
	std::vector<PointerBankEntry> entries;
	uint64_t sentinelOffset;
	std::vector<uint8_t> data;
};

struct PointerBankStore
{
	uint32_t fileOffset, before, after;
};

/* Visits and stores preserve original order and repetitions; unnamed node/payload fields remain in data. */
struct PointerBankView
{
	std::vector<uint8_t> data;
	std::vector<uint32_t> nodeVisits;
	std::vector<uint32_t> payloadVisits;
	std::vector<PointerBankStore> stores;
};

PointerBank readPointerBank(const std::vector<uint8_t>& rBytes_);
PointerBank readPointerBankPrsFile(GameCube::GCDisc& rDisc_, const std::string& path_);

/* Reproduce bounded self-contained pointer adjustment at a declared high-bit base; no native registry or rendering. */
PointerBankView buildPointerBankView(const PointerBank& rBank_, uint32_t base_);
}
