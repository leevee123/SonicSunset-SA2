#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace GameCube { struct GCDisc; }

namespace SA2
{
/* Optional GVMH fields retain their raw values; absent fields are not synthesized. */
struct GvmEntry
{
	uint16_t index;
	std::optional<std::string> name;
	std::optional<uint16_t> formatMetadata;
	std::optional<uint16_t> dimensionMetadata;
	std::optional<uint32_t> globalIndex;
};

/* Offsets address the unchanged native GX payload, including tile padding, not decoded RGBA pixels. */
struct GvmMip
{
	uint16_t width, height;
	uint64_t offset, size;
};

struct GvmTexture
{
	GvmEntry entry;
	uint64_t sourceOffset;
	uint16_t reserved;
	uint8_t dataFlags, format;
	uint16_t width, height;
	std::vector<uint8_t> data;
	std::vector<GvmMip> mips;
};

/* The original skips length-delimited chunks before the first GVRT; their contents stay opaque. */
struct GvmChunk
{
	std::array<uint8_t, 4> magic;
	std::vector<uint8_t> data;
};

struct GvmArchive
{
	uint16_t flags;
	std::vector<GvmTexture> textures;
	std::vector<uint8_t> headerPadding;
	std::vector<GvmChunk> skippedChunks;
	std::vector<uint8_t> trailingBytes;
};

/* Standalone GBIX lengths are rounded down to four bytes by FUN_80116204; the last BE global id wins. */
struct GvrGbix
{
	uint32_t declaredSize;
	std::vector<uint8_t> data;
};

struct GvrFile
{
	std::optional<uint32_t> globalIndex;
	std::vector<GvrGbix> gbixChunks;
	GvmTexture texture;
	std::vector<uint8_t> trailingBytes;
};

/* GSNE8P revision 0 GVMH/GVRT container and native mip layout; no GPU upload or palette guessing. */
GvmArchive readGvm(const std::vector<uint8_t>& rBytes_);
GvmArchive readGvmPrsFile(GameCube::GCDisc& rDisc_, const std::string& path_);
GvrFile readGvr(const std::vector<uint8_t>& rBytes_);
GvrFile readGvrFile(GameCube::GCDisc& rDisc_, const std::string& path_);
}
