#pragma once
#include "Gvm.h"
#include "Graphics/Resources/TextureMip.h"
#include <array>
#include <span>

namespace SA2
{
using TextureColor = std::array<uint8_t, 4>;

/* Explicit RGB565 interpretation of native palette words; this does not assign meaning to a GVP header or slot. */
std::vector<TextureColor> decodeRGB565Palette(std::span<const uint8_t> data_);

/* GX RGB5A3/CMPR/C4 pixels and every original mip. C4 requires an explicit 16-color RGBA palette. */
std::vector<Graphics::TextureMip> decodeTexture(const GvmTexture& rTexture_, std::span<const TextureColor> palette_ = {});
}
