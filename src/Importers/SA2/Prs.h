#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace GameCube
{
struct GCDisc;
}

namespace SA2
{
/* Retail SA2 Battle PRS streams, verified against FUN_800d2684 (GSNE8P revision 0). */
std::vector<uint8_t> decompressPrs(const std::vector<uint8_t>& rSrc_);
std::vector<uint8_t> readPrsFile(GameCube::GCDisc& rDisc_, const std::string& path_);
}
