#include "Importers/SA2/ModelVertexTransform.h"
#include "Importers/SA2/ModelData.h"
#include "BinaryRead.h"
#include <bit>
#include <cfenv>
#include <cmath>
#include <limits>
#include <stdexcept>

namespace SA2
{
static_assert(sizeof(float) == 4 && std::numeric_limits<float>::is_iec559);

/* Native helpers have no file/scratch guards. This copied-memory path rejects unsafe input before exposing a result. */
static void requireTransformBytes(uint64_t offset_, uint64_t size_, uint64_t end_)
{
	if(offset_ > end_ || size_ > end_ - offset_)
	{
		throw std::runtime_error("SA2 ModelVertexTransform: bytes exceed the available span.");
	}
}

/* The finite contract avoids inventing original NaN payload, exception and overflow behavior. Subnormal inputs remain valid. */
static float transformFloat(uint32_t word_)
{
	if((word_ & 0x7F800000) == 0x7F800000)
	{
		throw std::runtime_error("SA2 ModelVertexTransform: nonfinite value is outside the explicit FP contract.");
	}
	return std::bit_cast<float>(word_);
}

/* NI=0 retains subnormal arithmetic. Check the host's rounding and both subnormal input/output handling without changing them. */
static void requireTransformFloatEnvironment()
{
	if(std::fegetround() != FE_TONEAREST)
	{
		throw std::runtime_error("SA2 ModelVertexTransform: host rounding must be nearest-even.");
	}
	volatile float minimum = std::numeric_limits<float>::min();
	volatile float half = 0.5f;
	volatile float subnormal = std::numeric_limits<float>::denorm_min();
	volatile float one = 1.0f;
	float outputProbe = minimum * half;
	float inputProbe = subnormal * one;
	if(std::bit_cast<uint32_t>(outputProbe) != 0x00400000 || std::bit_cast<uint32_t>(inputProbe) != 1)
	{
		throw std::runtime_error("SA2 ModelVertexTransform: host subnormal arithmetic must be enabled.");
	}
}

/* Each PS arithmetic result rounds to binary32; no reassociation of the three native steps is allowed. */
static float transformFma(float left_, float right_, float addend_)
{
	float result = std::fma(left_, right_, addend_);
	transformFloat(std::bit_cast<uint32_t>(result));
	return result;
}

/* GQR0 float psq_st flushes subnormal output to signed zero even when the arithmetic NI bit is zero. */
static void storeTransformFloat(std::vector<uint8_t>& rScratch_, uint64_t offset_, float value_)
{
	uint32_t word = std::bit_cast<uint32_t>(value_);
	if((word & 0x7F800000) == 0) word &= 0x80000000;
	for(uint32_t i = 0; i < 4; i++)
	{
		rScratch_[offset_ + i] = static_cast<uint8_t>(word >> (24 - i * 8));
	}
}

/* Original 8011D1D4 supplies count/start from the info word; DA30/DAF0 use 16/24-byte records and 32-byte scratch slots. */
ModelVertexTransformResult transformModelVertexPacketFloat32(const std::vector<uint8_t>& rBytes_, uint64_t offset_, const ModelVertexMatrixFloat32& rMatrix_, const std::vector<uint8_t>& rScratch_)
{
	requireTransformBytes(offset_, 8, rBytes_.size());
	uint32_t header = readBE<uint32_t>(rBytes_, offset_);
	uint8_t opcode = static_cast<uint8_t>(header);
	if(opcode != 0x23 && opcode != 0x29)
	{
		throw std::runtime_error("SA2 ModelVertexTransform: opcode has no supported Float32 helper.");
	}
	uint64_t byteSize = (uint64_t(header >> 16) + 1) * 4;
	requireTransformBytes(offset_, byteSize, rBytes_.size());
	uint32_t info = readBE<uint32_t>(rBytes_, offset_ + 4);
	uint16_t count = static_cast<uint16_t>(info >> 16);
	uint16_t first = static_cast<uint16_t>(info);
	uint32_t stride = opcode == 0x23 ? 16 : 24;
	if(count == 0) throw std::runtime_error("SA2 ModelVertexTransform: zero count has no bounded native iteration.");
	requireTransformBytes(8, uint64_t(count) * stride, byteSize);
	requireTransformBytes(uint64_t(first) * 32, uint64_t(count) * 32, rScratch_.size());
	requireTransformFloatEnvironment();
	std::array<float, 12> matrix;
	for(uint32_t i = 0; i < matrix.size(); i++) matrix[i] = transformFloat(rMatrix_.words[i]);
	ModelVertexTransformResult result{first, count, opcode, rScratch_};
	for(uint32_t record = 0; record < count; record++)
	{
		uint64_t input = offset_ + 8 + uint64_t(record) * stride;
		uint64_t output = uint64_t(first + record) * 32;
		std::array<float, 6> values{};
		for(uint32_t i = 0; i < (opcode == 0x23 ? 3u : 6u); i++)
		{
			values[i] = transformFloat(readBE<uint32_t>(rBytes_, input + i * 4));
		}
		/* Both helpers add translation in the first fused step, then apply the second and third columns in order. */
		for(uint32_t row = 0; row < 3; row++)
		{
			float value = transformFma(matrix[row], values[0], matrix[9 + row]);
			value = transformFma(matrix[3 + row], values[1], value);
			value = transformFma(matrix[6 + row], values[2], value);
			storeTransformFloat(result.scratch, output + row * 4, value);
		}
		if(opcode == 0x29)
		{
			/* DAF0's second triple begins with a separately rounded product and receives no translation. */
			for(uint32_t row = 0; row < 3; row++)
			{
				float value = matrix[row] * values[3];
				transformFloat(std::bit_cast<uint32_t>(value));
				value = transformFma(matrix[3 + row], values[4], value);
				value = transformFma(matrix[6 + row], values[5], value);
				storeTransformFloat(result.scratch, output + 12 + row * 4, value);
			}
		}
		else
		{
			/* DA30 uses an integer word rotate, without interpreting the packed word as floating point. */
			uint32_t word = readBE<uint32_t>(rBytes_, input + 12);
			word = std::rotl(word, 8);
			for(uint32_t i = 0; i < 4; i++) result.scratch[output + 24 + i] = static_cast<uint8_t>(word >> (24 - i * 8));
		}
	}
	return result;
}

/* Weighted initialization and the second triple each require a separately rounded binary32 product. */
static float weightedTransformProduct(float left_, float right_)
{
	float result = left_ * right_;
	transformFloat(std::bit_cast<uint32_t>(result));
	return result;
}

/*
Original 8011DC98 consumes 28-byte records and adds each unsigned destination to the dispatcher's scratch base.
Its GQR1 overwrite makes every signed16 weight exactly value/256; no normalization or complementary weight is added.
Host bounds and finite guards exclude native aliases, discarded lanes, unused preloads, faults and count-zero traversal.
*/
ModelWeightedVertexTransformResult transformModelWeightedVertexPacketFloat32(const std::vector<uint8_t>& rBytes_, uint64_t offset_, const ModelVertexMatrixFloat32& rMatrix_, const std::vector<uint8_t>& rScratch_)
{
	requireTransformBytes(offset_, 8, rBytes_.size());
	uint32_t header = readBE<uint32_t>(rBytes_, offset_);
	if(static_cast<uint8_t>(header) != 0x2C)
	{
		throw std::runtime_error("SA2 ModelVertexTransform: packet has no weighted Float32 helper.");
	}
	uint64_t byteSize = (uint64_t(header >> 16) + 1) * 4;
	requireTransformBytes(offset_, byteSize, rBytes_.size());
	uint32_t info = readBE<uint32_t>(rBytes_, offset_ + 4);
	uint16_t count = static_cast<uint16_t>(info >> 16);
	uint16_t base = static_cast<uint16_t>(info);
	uint8_t variant = static_cast<uint8_t>((header & 0x7FFF) >> 8);
	if(count == 0) throw std::runtime_error("SA2 ModelVertexTransform: zero count has no bounded native iteration.");
	requireTransformBytes(8, uint64_t(count) * 28, byteSize);
	requireTransformFloatEnvironment();
	std::array<float, 12> matrix;
	for(uint32_t i = 0; i < matrix.size(); i++) matrix[i] = transformFloat(rMatrix_.words[i]);
	ModelWeightedVertexTransformResult result{base, count, variant, rScratch_};
	for(uint32_t record = 0; record < count; record++)
	{
		uint64_t input = offset_ + 8 + uint64_t(record) * 28;
		uint32_t destination = readBE<uint16_t>(rBytes_, input + 26);
		uint64_t output = uint64_t(base + destination) * 32;
		requireTransformBytes(output, 32, result.scratch.size());
		std::array<float, 6> values;
		for(uint32_t i = 0; i < values.size(); i++)
		{
			values[i] = transformFloat(readBE<uint32_t>(rBytes_, input + i * 4));
		}
		uint16_t rawWeight = readBE<uint16_t>(rBytes_, input + 24);
		int32_t signedWeight = rawWeight < 0x8000 ? int32_t(rawWeight) : int32_t(rawWeight) - 0x10000;
		float weight = static_cast<float>(signedWeight) * 0.00390625f;
		std::array<float, 6> transformed;
		/* Preserve the native translation-first fused order and the second triple's independent first product. */
		for(uint32_t row = 0; row < 3; row++)
		{
			float first = transformFma(matrix[row], values[0], matrix[9 + row]);
			first = transformFma(matrix[3 + row], values[1], first);
			transformed[row] = transformFma(matrix[6 + row], values[2], first);
			float second = weightedTransformProduct(matrix[row], values[3]);
			second = transformFma(matrix[3 + row], values[4], second);
			transformed[3 + row] = transformFma(matrix[6 + row], values[5], second);
		}
		std::array<float, 6> previous{};
		if(variant != 0)
		{
			/* All previous components are read before this record stores; repeated destinations see earlier records' flushed bytes. */
			for(uint32_t i = 0; i < previous.size(); i++)
			{
				previous[i] = transformFloat(readBE<uint32_t>(result.scratch, output + i * 4));
			}
		}
		/* Any nonzero variant uses a fused weighted accumulation; initialization never reads previous float components. */
		for(uint32_t i = 0; i < transformed.size(); i++)
		{
			float value = variant == 0 ? weightedTransformProduct(transformed[i], weight) : transformFma(transformed[i], weight, previous[i]);
			storeTransformFloat(result.scratch, output + i * 4, value);
		}
	}
	return result;
}

/*
The raw reader preserves native END-before-info and encoded stepping, including info overlapping a four-byte unknown packet.
Modeled state follows original D1D4 ordering; it remains caller-owned data rather than an inferred live SDA binding.
Each returned scratch becomes the next packet's input, preserving cross-packet accumulation and final-store rounding.
*/
ModelVertexStreamTransformResult transformModelVertexStreamFloat32(const std::vector<uint8_t>& rBytes_, uint64_t offset_, const ModelVertexMatrixFloat32& rMatrix_, const std::vector<uint8_t>& rScratch_, uint32_t initialStateBits_, uint32_t initialGqr1Word_)
{
	auto stream = readModelVertexStream(rBytes_, offset_);
	ModelVertexStreamTransformResult result{stream.endOffset, initialStateBits_, initialGqr1Word_, rScratch_};
	for(const auto& packet : stream.packets)
	{
		uint8_t opcode = packet.opcode();
		if(packet.isEnd()) break;
		if(opcode == 0x23 || opcode == 0x29)
		{
			if(opcode == 0x23) result.stateBits |= 3;
			auto transformed = transformModelVertexPacketFloat32(rBytes_, packet.fileOffset, rMatrix_, result.scratch);
			result.scratch.swap(transformed.scratch);
		}
		else if(opcode == 0x2C)
		{
			result.gqr1Word = 0x08070807;
			auto transformed = transformModelWeightedVertexPacketFloat32(rBytes_, packet.fileOffset, rMatrix_, result.scratch);
			result.scratch.swap(transformed.scratch);
		}
		else if(opcode == 0x2A)
		{
			throw std::runtime_error("SA2 ModelVertexTransform: stream contains an unvalidated 2A helper.");
		}
	}
	return result;
}
}
