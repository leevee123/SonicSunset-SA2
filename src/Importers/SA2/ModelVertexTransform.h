#pragma once
#include <array>
#include <cstdint>
#include <vector>

namespace SA2
{
/* Native 8011DA30/8011DAF0 load three contiguous columns followed by translation; keep the caller's binary32 bits. */
struct ModelVertexMatrixFloat32
{
	std::array<uint32_t, 12> words;
};

/* Scratch is an owned copy of native BE 32-byte slots, including all bytes the selected helper leaves untouched. */
struct ModelVertexTransformResult
{
	uint16_t firstScratchIndex, recordCount;
	uint8_t opcode;
	std::vector<uint8_t> scratch;
};

/*
Explicit contract: GQR0=0, nearest-even arithmetic, NI=0 and nontrapping FP; finite inputs and retained-lane results only.
The caller supplies the native-layout matrix and initial scratch; this does not select live state or run weighted op2C.
Host bounds/zero-count guards replace unsafe native memory access; aliases, unused preloads/lanes and FPSCR flags are excluded.
*/
ModelVertexTransformResult transformModelVertexPacketFloat32(const std::vector<uint8_t>& rBytes_, uint64_t offset_, const ModelVertexMatrixFloat32& rMatrix_, const std::vector<uint8_t>& rScratch_);

/* The info low halfword is an additive base; each weighted record supplies its own unsigned destination index. */
struct ModelWeightedVertexTransformResult
{
	uint16_t baseScratchIndex, recordCount;
	uint8_t variant;
	std::vector<uint8_t> scratch;
};

/*
Native 8011DC98 sets GQR1 to 08070807 and leaves it set: signed16 weights load exactly as value/256.
Under the same explicit Float32 contract, variant zero overwrites and every nonzero variant fuses accumulation.
Record order is preserved, including repeated destinations reading earlier final-store results from the copied scratch.
*/
ModelWeightedVertexTransformResult transformModelWeightedVertexPacketFloat32(const std::vector<uint8_t>& rBytes_, uint64_t offset_, const ModelVertexMatrixFloat32& rMatrix_, const std::vector<uint8_t>& rScratch_);

/* End offset includes the stored END word; state/GQR1 describe modeled native effects without touching engine globals. */
struct ModelVertexStreamTransformResult
{
	uint64_t endOffset;
	uint32_t stateBits, gqr1Word;
	std::vector<uint8_t> scratch;
};

/*
Original 8011D1D4 processes one first stream. The caller explicitly supplies its fixed nonaliased matrix and initial state.
This copied CPU path handles 23/29/2C, skips unknown opcodes by their stored span and rejects the unvalidated 2A helper.
The same Float32 contract and host guards apply; live global bindings, native aliases and external mutations are excluded.
*/
ModelVertexStreamTransformResult transformModelVertexStreamFloat32(const std::vector<uint8_t>& rBytes_, uint64_t offset_, const ModelVertexMatrixFloat32& rMatrix_, const std::vector<uint8_t>& rScratch_, uint32_t initialStateBits_, uint32_t initialGqr1Word_);
}
