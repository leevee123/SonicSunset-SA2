#include "ChaoPalette.h"
#include "BinaryRead.h"
#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace SA2
{
/* ChaoMain.prs +0x1FD60/+0x1FD70/+0x1FD80 mask and replicate the original 6/5/4-bit components. */
static uint8_t expandChaoColor(uint16_t value_, uint32_t bits_)
{
	uint32_t value = value_ & ((1u << bits_) - 1);
	return static_cast<uint8_t>((value << (8 - bits_)) | (value >> (2 * bits_ - 8)));
}

/* The original always converts 48 colors, ignoring the remaining header fields. Bounds checks precede any bank mutation. */
void updateChaoPalette(ChaoPaletteBank& rBank_, const GvpPalette& rPalette_)
{
	uint16_t mode = rPalette_.headerFields[0];
	if(mode != 0 && mode != 1 && mode != 2 && mode != 6)
	{
		throw std::runtime_error("SA2 ChaoPalette: unsupported native conversion mode.");
	}
	if(rPalette_.data.size() < (mode == 6 ? 48u : 96u))
	{
		throw std::runtime_error("SA2 ChaoPalette: native palette data is truncated.");
	}
	/* Mode 6 calls the original byte-copy helper with 0x30, leaving the final 144 bank bytes untouched. */
	if(mode == 6)
	{
		std::copy_n(rPalette_.data.begin(), 48, rBank_.bgra.begin());
		return;
	}
	/* Native BE words become BGRA. Mode 0's high alpha bit is inverted, as in +0x1FD90. */
	for(uint32_t i = 0; i < 48; i++)
	{
		uint16_t word = readBE<uint16_t>(rPalette_.data, i * 2);
		uint32_t offset = i * 4;
		if(mode == 0)
		{
			rBank_.bgra[offset] = expandChaoColor(word, 5);
			rBank_.bgra[offset + 1] = expandChaoColor(word >> 5, 5);
			rBank_.bgra[offset + 2] = expandChaoColor(word >> 10, 5);
			rBank_.bgra[offset + 3] = (word & 0x8000) ? 0 : 255;
		}
		else if(mode == 1)
		{
			rBank_.bgra[offset] = expandChaoColor(word, 5);
			rBank_.bgra[offset + 1] = expandChaoColor(word >> 5, 6);
			rBank_.bgra[offset + 2] = expandChaoColor(word >> 11, 5);
			rBank_.bgra[offset + 3] = 255;
		}
		else
		{
			rBank_.bgra[offset] = expandChaoColor(word, 4);
			rBank_.bgra[offset + 1] = expandChaoColor(word >> 4, 4);
			rBank_.bgra[offset + 2] = expandChaoColor(word >> 8, 4);
			rBank_.bgra[offset + 3] = expandChaoColor(word >> 12, 4);
		}
	}
}

/* The engine's CPU texture decoder accepts RGBA colors; retain the native BGRA bank separately. */
std::array<TextureColor, 48> chaoPaletteColors(const ChaoPaletteBank& rBank_)
{
	std::array<TextureColor, 48> colors;
	for(uint32_t i = 0; i < 48; i++)
	{
		uint32_t offset = i * 4;
		colors[i] = {rBank_.bgra[offset + 2], rBank_.bgra[offset + 1], rBank_.bgra[offset], rBank_.bgra[offset + 3]};
	}
	return colors;
}

/* +0x1F3C4/+0x1F870 replace either signed zero with the stored f32 epsilon, then ordered branches clamp to [-1,1]. */
static float chaoPaletteAxis(float value_)
{
	if(value_ == 0.0f)
	{
		value_ = 1.0e-6f;
	}
	if(value_ > 1.0f)
	{
		return 1.0f;
	}
	if(value_ < -1.0f)
	{
		return -1.0f;
	}
	return value_;
}

/* Native fctiwz truncates to signed 32 bits, saturates invalid conversions, then rlwinm keeps only the low byte. */
static uint8_t chaoPaletteByte(float value_)
{
	if(std::isnan(value_) || value_ < -2147483648.0f)
	{
		return 0;
	}
	if(value_ >= 2147483648.0f)
	{
		return 255;
	}
	return static_cast<uint8_t>(static_cast<uint32_t>(static_cast<int32_t>(value_)));
}

/* Explicit std::fma calls match fmadds; separate float products match fmuls before each fused addition. */
bool buildChaoPalette(ChaoPalette& rPalette_, std::span<const ChaoPaletteBank, 39> banks_, const ChaoPaletteParameters& rParameters_)
{
	uint32_t base;
	switch(rParameters_.type)
	{
	case 2: base = 0; break;
	case 6: base = 9; break;
	case 9: base = 15; break;
	case 12: base = 21; break;
	case 15: base = 27; break;
	case 18: base = 33; break;
	default: return false;
	}
	/* +0x1F3B4/+0x1F854 branch when GT is clear, preserving NaN and negative C0 while clamping only values above 1. */
	float weight = rParameters_.valueC0;
	if(weight > 1.0f)
	{
		weight = 1.0f;
	}
	float x = chaoPaletteAxis(rParameters_.valueA8);
	float y = chaoPaletteAxis(rParameters_.valueAC);
	uint32_t bankX = base + (base == 0 ? 7 : 5);
	uint32_t bankY = base + (base == 0 ? 5 : 3);
	if(x < 0.0f)
	{
		bankX--;
		x = -x;
	}
	if(y < 0.0f)
	{
		bankY--;
		y = -y;
	}
	float inverse = 1.0f / (x + y);
	float weightX = inverse * x;
	float weightY = inverse * y;
	float remainingX = 1.0f - x;
	float remainingY = 1.0f - y;
	float remainingWeight = 1.0f - weight;
	float type2Weight = 0.0f;
	bool negativeType2 = false;
	if(base == 0)
	{
		type2Weight = rParameters_.valueB0;
		negativeType2 = !(type2Weight >= 0.0f);
		/* +0x1F4A4 routes unordered B0 through the negative branch; +0x1F658 clamps only values below -1. */
		if(negativeType2)
		{
			if(type2Weight < -1.0f)
			{
				type2Weight = -1.0f;
			}
			type2Weight = type2Weight * -1.0f;
		}
		else if(type2Weight > 1.0f)
		{
			type2Weight = 1.0f;
		}
	}
	float remainingType2 = 1.0f - type2Weight;
	ChaoPalette result;
	/* All four BGRA components are processed; the original selector uses B/G/R and discards alpha before RGB565 packing. */
	for(uint32_t color = 0; color < 48; color++)
	{
		std::array<uint8_t, 4> components;
		for(uint32_t component = 0; component < 4; component++)
		{
			uint32_t offset = color * 4 + component;
			float normal = static_cast<float>(banks_[base].bgra[offset]);
			float morph = static_cast<float>(banks_[base + 1].bgra[offset]);
			float value;
			if(base == 0 && negativeType2)
			{
				/* +0x1F6D8..+0x1F6F0: normal/morph blend, then the ninth bank, preserving both fused additions. */
				float weightedMorph = morph * weight;
				float lower = std::fma(normal, remainingWeight, weightedMorph);
				float special = static_cast<float>(banks_[8].bgra[offset]) * type2Weight;
				value = std::fma(lower, remainingType2, special);
			}
			else
			{
				/* +0x1F568..+0x1F594 and +0x1F9E8..+0x1FA04 evaluate Y before the fused X contribution. */
				float shared = static_cast<float>(banks_[base == 0 ? 3 : base + 1].bgra[offset]);
				float selectedY = static_cast<float>(banks_[bankY].bgra[offset]) * y;
				float partY = std::fma(shared, remainingY, selectedY);
				float selectedX = static_cast<float>(banks_[bankX].bgra[offset]) * x;
				float partX = std::fma(shared, remainingX, selectedX);
				float weightedY = weightY * partY;
				float mix = std::fma(weightX, partX, weightedY);
				float weightedMix = mix * weight;
				if(base == 0)
				{
					/* +0x1F5BC..+0x1F5C8 blends the third bank with the morph result before the final type-2 blend. */
					float upper = std::fma(static_cast<float>(banks_[2].bgra[offset]), remainingWeight, weightedMix);
					float weightedMorph = morph * weight;
					float lower = std::fma(normal, remainingWeight, weightedMorph);
					float weightedUpper = upper * type2Weight;
					value = std::fma(lower, remainingType2, weightedUpper);
				}
				else
				{
					value = std::fma(normal, remainingWeight, weightedMix);
				}
			}
			components[component] = chaoPaletteByte(value);
		}
		uint16_t word = static_cast<uint16_t>(((components[2] >> 3) << 11) | ((components[1] >> 2) << 5) | (components[0] >> 3));
		result.rgb565[color * 2] = static_cast<uint8_t>(word >> 8);
		result.rgb565[color * 2 + 1] = static_cast<uint8_t>(word);
	}
	rPalette_ = result;
	return true;
}

/* +0x1FAB4 creates TLUT format 1/count 16 and advances the 96-byte output by 0x20 for each of three uploads. */
std::array<TextureColor, 16> chaoPaletteGroupColors(const ChaoPalette& rPalette_, uint32_t group_)
{
	if(group_ >= 3)
	{
		throw std::runtime_error("SA2 ChaoPalette: native TLUT group is outside 0..2.");
	}
	std::array<TextureColor, 16> colors;
	for(uint32_t color = 0; color < 16; color++)
	{
		uint32_t offset = group_ * 32 + color * 2;
		uint16_t word = static_cast<uint16_t>((rPalette_.rgb565[offset] << 8) | rPalette_.rgb565[offset + 1]);
		colors[color] = {expandChaoColor(word >> 11, 5), expandChaoColor(word >> 5, 6), expandChaoColor(word, 5), 255};
	}
	return colors;
}
}
