#include "Importers/SA2/ModelVertexTransform.h"
#include <bit>
#include <cfenv>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>

static std::vector<uint8_t> load(const std::string& path_)
{
	std::ifstream file(path_, std::ios::binary);
	if(!file) throw std::runtime_error("Cannot open input.");
	return {std::istreambuf_iterator<char>(file), {}};
}

static void save(const std::string& path_, const std::vector<uint8_t>& bytes_)
{
	std::ofstream file(path_, std::ios::binary);
	file.write(reinterpret_cast<const char*>(bytes_.data()), static_cast<std::streamsize>(bytes_.size()));
	if(!file) throw std::runtime_error("Cannot write output.");
}

static std::vector<uint8_t> packet(uint8_t opcode_, uint16_t count_, uint16_t first_, const std::array<uint32_t, 6>& values_)
{
	uint32_t stride = opcode_ == 0x23 ? 16 : 24;
	std::vector<uint8_t> bytes(8 + uint32_t(count_) * stride);
	auto put = [&](uint32_t offset, uint32_t word) {
		for(uint32_t i = 0; i < 4; i++) bytes.at(offset + i) = static_cast<uint8_t>(word >> (24 - i * 8));
	};
	put(0, (static_cast<uint32_t>(bytes.size() / 4 - 1) << 16) | opcode_);
	put(4, (uint32_t(count_) << 16) | first_);
	for(uint32_t record = 0; record < count_; record++)
		for(uint32_t i = 0; i < stride / 4; i++) put(8 + record * stride + i * 4, values_[i]);
	return bytes;
}

static void fixtures()
{
	SA2::ModelVertexMatrixFloat32 matrix{{0x3F800000, 0, 0, 0, 0x3F800000, 0, 0, 0, 0x3F800000, 0, 0, 0}};
	std::vector<uint8_t> scratch(128, 0xA5);
	uint32_t preserved = 0, rejected = 0;
	auto reject = [&](const std::vector<uint8_t>& bytes, uint64_t offset, const SA2::ModelVertexMatrixFloat32& inputMatrix, const std::vector<uint8_t>& initial) {
		try { SA2::transformModelVertexPacketFloat32(bytes, offset, inputMatrix, initial); }
		catch(const std::runtime_error&) { rejected++; return; }
		throw std::runtime_error("Expected host rejection.");
	};
	/* These check meaningful quirks and host boundaries; original-word references independently check arithmetic and full scratch bytes. */
	auto input = packet(0x23, 1, 1, {0x3F800000, 0x40000000, 0x40400000, 0x12345678, 0, 0});
	auto result = SA2::transformModelVertexPacketFloat32(input, 0, matrix, scratch);
	if(result.firstScratchIndex != 1 || result.recordCount != 1 || result.opcode != 0x23 || result.scratch[56] != 0x34 || result.scratch[59] != 0x12) throw std::runtime_error("Packed rotate/metadata failed.");
	for(uint32_t i = 0; i < scratch.size(); i++)
		if((i < 32 || i >= 64 || (i >= 44 && i < 56) || i >= 60) && result.scratch[i] != 0xA5) throw std::runtime_error("Untouched byte changed.");
	if(scratch != std::vector<uint8_t>(128, 0xA5)) throw std::runtime_error("Caller scratch changed.");
	preserved++;
	auto zero = packet(0x29, 1, 0, {1, 0x80000001, 0, 1, 0x80000001, 0});
	auto flushed = SA2::transformModelVertexPacketFloat32(zero, 0, matrix, scratch);
	if(flushed.scratch[3] != 0 || flushed.scratch[15] != 0) throw std::runtime_error("Subnormal store failed.");
	preserved++;
	auto padded = input; padded.insert(padded.end(), {0xDE, 0xAD, 0xBE, 0xEF});
	if(SA2::transformModelVertexPacketFloat32(padded, 0, matrix, scratch).scratch != result.scratch) throw std::runtime_error("Trailing bytes affected helper.");
	preserved++;
	auto prefix = input; prefix.insert(prefix.begin(), {0, 1, 2});
	if(SA2::transformModelVertexPacketFloat32(prefix, 3, matrix, scratch).scratch != result.scratch) throw std::runtime_error("Offset failed.");
	preserved++;
	auto aliasBytes = input; aliasBytes.resize(128, 0xA5);
	auto beforeAlias = aliasBytes;
	SA2::transformModelVertexPacketFloat32(aliasBytes, 0, matrix, aliasBytes);
	if(aliasBytes != beforeAlias) throw std::runtime_error("Immutable alias changed.");
	preserved++;
	reject({}, 0, matrix, scratch);
	reject(input, UINT64_MAX, matrix, scratch);
	reject(input, 1, matrix, scratch);
	auto bad = input; bad[3] = 0x2C; reject(bad, 0, matrix, scratch);
	bad = input; bad[0] = 0xFF; reject(bad, 0, matrix, scratch);
	bad = input; bad[1] = 0; reject(bad, 0, matrix, scratch);
	bad = input; bad[4] = 0; bad[5] = 0; reject(bad, 0, matrix, scratch);
	bad = input; bad.pop_back(); reject(bad, 0, matrix, scratch);
	reject(input, 0, matrix, std::vector<uint8_t>(63));
	bad = input; bad[8] = 0x7F; bad[9] = 0x80; bad[10] = 0; bad[11] = 0; reject(bad, 0, matrix, scratch);
	bad = input; bad[8] = 0x7F; bad[9] = 0xC0; bad[10] = 0; bad[11] = 1; reject(bad, 0, matrix, scratch);
	auto invalidMatrix = matrix; invalidMatrix.words[0] = 0xFF800000; reject(input, 0, invalidMatrix, scratch);
	invalidMatrix = matrix; invalidMatrix.words[9] = 0x7FC00001; reject(input, 0, invalidMatrix, scratch);
	invalidMatrix = matrix; invalidMatrix.words[0] = 0x7F7FFFFF;
	bad = input; bad[8] = 0x7F; bad[9] = 0x7F; bad[10] = 0xFF; bad[11] = 0xFF; reject(bad, 0, invalidMatrix, scratch);
	int priorRounding = std::fegetround();
	if(std::fesetround(FE_DOWNWARD) != 0) throw std::runtime_error("Cannot set test rounding.");
	reject(input, 0, matrix, scratch);
	if(std::fesetround(priorRounding) != 0) throw std::runtime_error("Cannot restore test rounding.");
	std::cout << "preserved=" << preserved << " rejected=" << rejected << "\n";
}

int main(int argc, char** argv)
{
	try
	{
		if(argc == 2 && std::string(argv[1]) == "--fixtures") { fixtures(); return 0; }
		if(argc != 7) throw std::runtime_error("Expected input, offset, matrix, initial scratch, output scratch, metadata.");
		auto input = load(argv[1]);
		auto initial = load(argv[4]);
		std::ifstream matrixFile(argv[3]);
		SA2::ModelVertexMatrixFloat32 matrix;
		std::string word;
		for(auto& value : matrix.words)
		{
			if(!(matrixFile >> word)) throw std::runtime_error("Matrix is truncated.");
			value = static_cast<uint32_t>(std::stoul(word, nullptr, 16));
		}
		auto result = SA2::transformModelVertexPacketFloat32(input, std::stoull(argv[2], nullptr, 0), matrix, initial);
		save(argv[5], result.scratch);
		std::ofstream metadata(argv[6]);
		metadata << result.firstScratchIndex << "," << result.recordCount << "," << uint32_t(result.opcode) << "\n";
		return 0;
	}
	catch(const std::exception& error)
	{
		std::cerr << error.what() << "\n";
		return 1;
	}
}
