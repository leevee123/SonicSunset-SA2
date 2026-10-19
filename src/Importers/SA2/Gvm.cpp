#include "Gvm.h"
#include "Importers/SA2/Prs.h"
#include "BinaryRead.h"
#include "GCDisc.h"
#include <algorithm>
#include <cstring>
#include <format>
#include <stdexcept>
#include <utility>

namespace SA2
{
/* Host bounds checks supplement the retail cursor helpers, which advance without checking the buffer. */
static void requireBytes(const std::vector<uint8_t>& rBytes_, uint64_t offset_, uint64_t size_)
{
	if(offset_ > rBytes_.size() || size_ > rBytes_.size() - offset_)
	{
		throw std::runtime_error(std::format("SA2 Gvm: {} bytes at 0x{:X} exceed the buffer.", size_, offset_));
	}
}

static std::vector<uint8_t> copyBytes(const std::vector<uint8_t>& rBytes_, uint64_t begin_, uint64_t end_)
{
	requireBytes(rBytes_, begin_, end_ - begin_);
	return {rBytes_.begin() + begin_, rBytes_.begin() + end_};
}

/* FUN_80118E28 sizes entries from bits 0..3; FUN_80118CEC reads BE indices/global values and skips metadata. */
static GvmEntry readEntry(const std::vector<uint8_t>& rBytes_, uint64_t& rCursor_, uint16_t flags_)
{
	GvmEntry entry;
	entry.index = readBE<uint16_t>(rBytes_, rCursor_);
	rCursor_ += 2;
	if(flags_ & 1)
	{
		requireBytes(rBytes_, rCursor_, 28);
		const char* name = reinterpret_cast<const char*>(rBytes_.data() + rCursor_);
		const char* end = static_cast<const char*>(std::memchr(name, 0, 28));
		entry.name = std::string(name, end ? end - name : 28);
		rCursor_ += 28;
	}
	if(flags_ & 2)
	{
		entry.formatMetadata = readBE<uint16_t>(rBytes_, rCursor_);
		rCursor_ += 2;
	}
	if(flags_ & 4)
	{
		entry.dimensionMetadata = readBE<uint16_t>(rBytes_, rCursor_);
		rCursor_ += 2;
	}
	if(flags_ & 8)
	{
		entry.globalIndex = readBE<uint32_t>(rBytes_, rCursor_);
		rCursor_ += 4;
	}
	return entry;
}

/*
FUN_80117808 rejects nonsquare mipmapped textures. FUN_801178A8 calls FUN_80103128 with a 100-level cap:
32-byte 4x4 tiles for format 5, 8x8 for 8/14, halve dimensions down to 1x1, rounding each level to whole tiles.
All native bytes, including the observed 16-byte suffix on some textures, remain in data (SA2_GVM_REFERENCE.md).
*/
static void readMips(GvmTexture& rTexture_)
{
	uint32_t tile;
	switch(rTexture_.format)
	{
	case 5: tile = 4; break;
	case 8:
	case 14: tile = 8; break;
	default: throw std::runtime_error(std::format("SA2 Gvm: unverified native format {}.", rTexture_.format));
	}
	if(rTexture_.width == 0 || rTexture_.height == 0 ||
		((rTexture_.dataFlags & 1) && rTexture_.width != rTexture_.height))
	{
		throw std::runtime_error("SA2 Gvm: invalid native texture dimensions.");
	}
	uint16_t width = rTexture_.width, height = rTexture_.height;
	uint64_t offset = 0;
	for(uint32_t level = 0; level < 100; level++)
	{
		uint64_t size = uint64_t((width + tile - 1) / tile) * ((height + tile - 1) / tile) * 32;
		if(offset > rTexture_.data.size() || size > rTexture_.data.size() - offset)
		{
			throw std::runtime_error("SA2 Gvm: native mip data is truncated.");
		}
		rTexture_.mips.push_back({width, height, offset, size});
		offset += size;
		if(!(rTexture_.dataFlags & 1) || (width == 1 && height == 1)) break;
		width = std::max<uint16_t>(1, static_cast<uint16_t>(width >> 1));
		height = std::max<uint16_t>(1, static_cast<uint16_t>(height >> 1));
	}
}

/* FUN_80118FC0 swaps only chunk magic/length words; GVRT fields at +8..+15 stay big-endian. */
static uint64_t readTexture(const std::vector<uint8_t>& rBytes_, uint64_t cursor_, GvmTexture& rTexture_)
{
	requireBytes(rBytes_, cursor_, 16);
	if(std::memcmp(rBytes_.data() + cursor_, "GVRT", 4) != 0)
	{
		throw std::runtime_error("SA2 Gvm: expected a GVRT block.");
	}
	uint32_t size = readLE<uint32_t>(rBytes_, cursor_ + 4);
	if(size < 8) throw std::runtime_error("SA2 Gvm: GVRT header is truncated.");
	requireBytes(rBytes_, cursor_ + 8, size);
	rTexture_.sourceOffset = cursor_;
	rTexture_.reserved = readBE<uint16_t>(rBytes_, cursor_ + 8);
	rTexture_.dataFlags = rBytes_[cursor_ + 10];
	rTexture_.format = rBytes_[cursor_ + 11];
	rTexture_.width = readBE<uint16_t>(rBytes_, cursor_ + 12);
	rTexture_.height = readBE<uint16_t>(rBytes_, cursor_ + 14);
	rTexture_.data = copyBytes(rBytes_, cursor_ + 16, cursor_ + 8 + size);
	readMips(rTexture_);
	return cursor_ + 8 + size;
}

/* FUN_80118FC0 honors the declared GVMH end; only positive signed counts and bounded host tables are supported. */
GvmArchive readGvm(const std::vector<uint8_t>& rBytes_)
{
	requireBytes(rBytes_, 0, 12);
	if(std::memcmp(rBytes_.data(), "GVMH", 4) != 0)
	{
		throw std::runtime_error("SA2 Gvm: not a GVMH archive.");
	}
	GvmArchive archive;
	archive.flags = readBE<uint16_t>(rBytes_, 8);
	uint16_t count = readBE<uint16_t>(rBytes_, 10);
	uint64_t headerEnd = uint64_t(readLE<uint32_t>(rBytes_, 4)) + 8;
	if(headerEnd < 12 || count == 0 || count > 0x7fff)
	{
		throw std::runtime_error("SA2 Gvm: invalid header size or unsupported entry count.");
	}
	requireBytes(rBytes_, 0, headerEnd);
	uint64_t stride = 2 + ((archive.flags & 1) ? 28 : 0) + ((archive.flags & 2) ? 2 : 0)
		+ ((archive.flags & 4) ? 2 : 0) + ((archive.flags & 8) ? 4 : 0);
	if(count * stride > headerEnd - 12)
	{
		throw std::runtime_error("SA2 Gvm: entry table exceeds the GVMH chunk.");
	}

	/* Retail texture ordinal i selects the first entry whose low 16-bit index equals i, not entry i. */
	archive.textures.resize(count);
	std::vector<uint16_t> entriesByIndex(count, 0xffff);
	uint64_t cursor = 12;
	for(uint16_t i = 0; i < count; i++)
	{
		GvmEntry entry = readEntry(rBytes_, cursor, archive.flags);
		if(entry.index >= count || entriesByIndex[entry.index] != 0xffff)
		{
			throw std::runtime_error("SA2 Gvm: entry indices are not a permutation.");
		}
		entriesByIndex[entry.index] = i;
		archive.textures[i].entry = std::move(entry);
	}
	archive.headerPadding = copyBytes(rBytes_, cursor, headerEnd);
	cursor = headerEnd;

	/* FUN_80118E78 skips any length-delimited chunk until the first GVRT, then rewinds its magic. */
	while(true)
	{
		requireBytes(rBytes_, cursor, 8);
		if(std::memcmp(rBytes_.data() + cursor, "GVRT", 4) == 0) break;
		uint32_t size = readLE<uint32_t>(rBytes_, cursor + 4);
		requireBytes(rBytes_, cursor + 8, size);
		GvmChunk chunk;
		std::memcpy(chunk.magic.data(), rBytes_.data() + cursor, 4);
		chunk.data = copyBytes(rBytes_, cursor + 8, cursor + 8 + size);
		archive.skippedChunks.push_back(std::move(chunk));
		cursor += 8 + size;
	}
	for(uint16_t i = 0; i < count; i++)
	{
		cursor = readTexture(rBytes_, cursor, archive.textures[entriesByIndex[i]]);
	}
	archive.trailingBytes = copyBytes(rBytes_, cursor, rBytes_.size());
	return archive;
}

GvmArchive readGvmPrsFile(GameCube::GCDisc& rDisc_, const std::string& path_)
{
	return readGvm(readPrsFile(rDisc_, path_));
}

/* FUN_80116204 accepts only repeated GBIX prefixes followed by GVRT, unlike the GVM prefix scanner. */
GvrFile readGvr(const std::vector<uint8_t>& rBytes_)
{
	GvrFile file{};
	uint64_t cursor = 0;
	while(true)
	{
		requireBytes(rBytes_, cursor, 8);
		if(std::memcmp(rBytes_.data() + cursor, "GVRT", 4) == 0) break;
		if(std::memcmp(rBytes_.data() + cursor, "GBIX", 4) != 0)
		{
			throw std::runtime_error("SA2 Gvr: expected GBIX or GVRT.");
		}
		uint32_t declaredSize = readLE<uint32_t>(rBytes_, cursor + 4);
		uint32_t size = declaredSize & 0xfffffffc;
		if(size < 4) throw std::runtime_error("SA2 Gvr: GBIX lacks its global index.");
		requireBytes(rBytes_, cursor + 8, size);
		file.globalIndex = readBE<uint32_t>(rBytes_, cursor + 8);
		file.gbixChunks.push_back({declaredSize, copyBytes(rBytes_, cursor + 8, cursor + 8 + size)});
		cursor += 8 + size;
	}
	cursor = readTexture(rBytes_, cursor, file.texture);
	file.trailingBytes = copyBytes(rBytes_, cursor, rBytes_.size());
	return file;
}

GvrFile readGvrFile(GameCube::GCDisc& rDisc_, const std::string& path_)
{
	return readGvr(rDisc_.readFile(path_));
}
}
