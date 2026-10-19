#include "Texture.h"
#include "BinaryRead.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace SA2
{
/* GX expands color bits by replication, not by scaling. Hardware reference and original upload addresses: SA2_TEXTURE_REFERENCE.md. */
static uint8_t expand(uint32_t value_, uint32_t bits_)
{
	return static_cast<uint8_t>((value_ << (8 - bits_)) | (value_ >> (2 * bits_ - 8)));
}

static TextureColor rgb565(uint16_t value_)
{
	return {expand(value_ >> 11, 5), expand((value_ >> 5) & 63, 6), expand(value_ & 31, 5), 255};
}

/* RGB5A3's high bit selects opaque RGB555; otherwise alpha is 3 bits and color is RGB444. */
static TextureColor rgb5a3(uint16_t value_)
{
	if(value_ & 0x8000)
	{
		return {expand((value_ >> 10) & 31, 5), expand((value_ >> 5) & 31, 5), expand(value_ & 31, 5), 255};
	}
	uint32_t alpha = (value_ >> 12) & 7;
	return {static_cast<uint8_t>(((value_ >> 8) & 15) * 17), static_cast<uint8_t>(((value_ >> 4) & 15) * 17),
		static_cast<uint8_t>((value_ & 15) * 17), static_cast<uint8_t>((alpha << 5) | (alpha << 2) | (alpha >> 1))};
}

std::vector<TextureColor> decodeRGB565Palette(std::span<const uint8_t> data_)
{
	if(data_.size() % 2 != 0) throw std::runtime_error("SA2 Texture: RGB565 palette has an incomplete word.");
	std::vector<TextureColor> colors;
	colors.reserve(data_.size() / 2);
	for(size_t i = 0; i < data_.size(); i += 2) colors.push_back(rgb565(static_cast<uint16_t>((uint32_t(data_[i]) << 8) | data_[i + 1])));
	return colors;
}

/* Native tiles include padding even for 1x1 mip levels; only visible pixels enter the decoded image. */
static void putPixel(Graphics::TextureMip& rMip_, uint32_t x_, uint32_t y_, const TextureColor& rColor_)
{
	if(x_ < rMip_.width && y_ < rMip_.height)
	{
		std::memcpy(rMip_.pixels.data() + (uint64_t(y_) * rMip_.width + x_) * 4, rColor_.data(), 4);
	}
}

/* GX CMPR uses 5/8 and 3/8 blends. Its transparent entry retains the endpoint average in RGB. */
static void decodeBlock(const std::vector<uint8_t>& rData_, uint64_t cursor_, Graphics::TextureMip& rMip_, uint32_t x_, uint32_t y_)
{
	uint16_t first = readBE<uint16_t>(rData_, cursor_), second = readBE<uint16_t>(rData_, cursor_ + 2);
	std::array<TextureColor, 4> colors;
	colors[0] = rgb565(first); colors[1] = rgb565(second);
	for(uint32_t channel = 0; channel < 3; channel++)
	{
		if(first > second)
		{
			colors[2][channel] = static_cast<uint8_t>((5 * colors[0][channel] + 3 * colors[1][channel]) >> 3);
			colors[3][channel] = static_cast<uint8_t>((3 * colors[0][channel] + 5 * colors[1][channel]) >> 3);
		}
		else
		{
			colors[2][channel] = colors[3][channel] = static_cast<uint8_t>((colors[0][channel] + colors[1][channel]) / 2);
		}
	}
	colors[2][3] = 255; colors[3][3] = first > second ? 255 : 0;
	for(uint32_t y = 0; y < 4; y++)
	{
		uint8_t row = rData_[cursor_ + 4 + y];
		for(uint32_t x = 0; x < 4; x++) putPixel(rMip_, x_ + x, y_ + y, colors[(row >> (6 - x * 2)) & 3]);
	}
}

/* Only verified retail formats are decoded. Indexed pixels require caller-supplied colors, never inferred palette bindings. */
std::vector<Graphics::TextureMip> decodeTexture(const GvmTexture& rTexture_, std::span<const TextureColor> palette_)
{
	if(rTexture_.format != 5 && rTexture_.format != 8 && rTexture_.format != 14)
	{
		throw std::runtime_error("SA2 Texture: unsupported native format.");
	}
	if(rTexture_.format == 8 && palette_.size() != 16)
	{
		throw std::runtime_error("SA2 Texture: C4 requires an explicit 16-color palette.");
	}
	if(rTexture_.mips.empty()) throw std::runtime_error("SA2 Texture: no native mip levels.");
	std::vector<Graphics::TextureMip> levels;
	for(const auto& mip : rTexture_.mips)
	{
		uint32_t tile = rTexture_.format == 5 ? 4 : 8;
		uint64_t needed = uint64_t((mip.width + tile - 1) / tile) * ((mip.height + tile - 1) / tile) * 32;
		if(mip.width == 0 || mip.height == 0 || mip.size != needed || mip.offset > rTexture_.data.size() || needed > rTexture_.data.size() - mip.offset)
		{
			throw std::runtime_error("SA2 Texture: invalid or truncated native mip span.");
		}
		Graphics::TextureMip image{mip.width, mip.height, std::vector<uint8_t>(uint64_t(mip.width) * mip.height * 4)};
		uint64_t cursor = mip.offset;
		/* Tiles run left to right, then top to bottom; CMPR contains four 4x4 blocks and C4 stores the left nibble first. */
		for(uint32_t tileY = 0; tileY < mip.height; tileY += tile)
		{
			for(uint32_t tileX = 0; tileX < mip.width; tileX += tile)
			{
				if(rTexture_.format == 14)
				{
					for(uint32_t block = 0; block < 4; block++) decodeBlock(rTexture_.data, cursor + block * 8, image, tileX + (block & 1) * 4, tileY + (block >> 1) * 4);
					cursor += 32;
				}
				else
				{
					for(uint32_t y = 0; y < tile; y++)
					{
						for(uint32_t x = 0; x < tile; x++)
						{
							if(rTexture_.format == 5)
							{
								putPixel(image, tileX + x, tileY + y, rgb5a3(readBE<uint16_t>(rTexture_.data, cursor)));
								cursor += 2;
							}
							else
							{
								uint8_t pair = rTexture_.data[cursor + y * 4 + x / 2];
								putPixel(image, tileX + x, tileY + y, palette_[(x & 1) ? pair & 15 : pair >> 4]);
							}
						}
					}
					if(rTexture_.format == 8) cursor += 32;
				}
			}
		}
		levels.push_back(std::move(image));
	}
	return levels;
}
}
