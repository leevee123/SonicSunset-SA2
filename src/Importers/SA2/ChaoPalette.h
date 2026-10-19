#pragma once
#include "Gvp.h"
#include "Importers/SA2/Texture.h"
#include <array>
#include <span>

namespace SA2
{
/* ChaoMain.prs +0x1FAF8 stores 48 BGRA colors per bank; an update can intentionally retain previous bytes. */
struct ChaoPaletteBank
{
	std::array<uint8_t, 192> bgra{};
};

/* Applies the native conversion mode in headerFields[0], including mode 6's partial 48-byte copy. */
void updateChaoPalette(ChaoPaletteBank& rBank_, const GvpPalette& rPalette_);

/* Exposes all 48 colors as RGBA; the caller supplies the texture's palette selection explicitly. */
std::array<TextureColor, 48> chaoPaletteColors(const ChaoPaletteBank& rBank_);

/* ChaoMain.prs +0x1F2E4 reads these fields from the data block; their gameplay names remain unknown. */
struct ChaoPaletteParameters
{
	uint8_t type{};
	float valueA8{};
	float valueAC{};
	float valueB0{};
	float valueC0{};
};

/* The native output is 48 BE RGB565 words, uploaded as three contiguous groups of 16 colors. */
struct ChaoPalette
{
	std::array<uint8_t, 96> rgb565{};
};

/* Preserves native single-precision/FMA order. Unsupported type bytes return false without changing the output. */
bool buildChaoPalette(ChaoPalette& rPalette_, std::span<const ChaoPaletteBank, 39> banks_, const ChaoPaletteParameters& rParameters_);

/* Converts one proven native TLUT group (0..2) for the existing explicit C4 texture decoder. */
std::array<TextureColor, 16> chaoPaletteGroupColors(const ChaoPalette& rPalette_, uint32_t group_);
}
