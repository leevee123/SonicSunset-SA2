#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace GameCube { struct GCDisc; }

namespace SA2
{
/* FUN_8011773C preserves all four BE words and the payload; Chao interprets the first word through its separate palette path. */
struct GvpPalette
{
	std::array<uint16_t, 4> headerFields;
	std::vector<uint8_t> data;
	std::vector<uint8_t> trailingBytes;
};

GvpPalette readGvp(const std::vector<uint8_t>& rBytes_);
GvpPalette readGvpFile(GameCube::GCDisc& rDisc_, const std::string& path_);
}
