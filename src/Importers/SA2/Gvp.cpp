#include "Gvp.h"
#include "BinaryRead.h"
#include "GCDisc.h"
#include <cstring>
#include <stdexcept>

namespace SA2
{
/* FUN_8011773C swaps only GVPL magic/length, copies length−8 bytes from +16, and reads four BE header words. */
GvpPalette readGvp(const std::vector<uint8_t>& rBytes_)
{
	if(rBytes_.size() < 16 || std::memcmp(rBytes_.data(), "GVPL", 4) != 0)
	{
		throw std::runtime_error("SA2 Gvp: not a GVPL palette.");
	}
	uint32_t size = readLE<uint32_t>(rBytes_, 4);
	uint64_t end = uint64_t(size) + 8;
	if(size < 8 || end > rBytes_.size())
	{
		throw std::runtime_error("SA2 Gvp: palette chunk is truncated.");
	}
	GvpPalette palette;
	for(uint32_t i = 0; i < 4; i++) palette.headerFields[i] = readBE<uint16_t>(rBytes_, 8 + i * 2);
	palette.data = {rBytes_.begin() + 16, rBytes_.begin() + end};
	palette.trailingBytes = {rBytes_.begin() + end, rBytes_.end()};
	return palette;
}

GvpPalette readGvpFile(GameCube::GCDisc& rDisc_, const std::string& path_)
{
	return readGvp(rDisc_.readFile(path_));
}
}
