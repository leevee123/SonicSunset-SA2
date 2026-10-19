#include "Importers/SA2/ModelVertexTransform.h"
#include <bit>
#include <cfenv>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>

struct Record
{
	std::array<uint32_t, 6> words;
	uint16_t weight, destination;
};

static std::vector<uint8_t> load(const std::string& path)
{
	std::ifstream file(path, std::ios::binary);
	if(!file) throw std::runtime_error("Cannot open input.");
	return {std::istreambuf_iterator<char>(file), {}};
}

static void save(const std::string& path, const std::vector<uint8_t>& bytes)
{
	std::ofstream file(path, std::ios::binary);
	file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
	if(!file) throw std::runtime_error("Cannot write output.");
}

static void put(std::vector<uint8_t>& bytes, uint32_t offset, uint32_t word, uint32_t size = 4)
{
	for(uint32_t i = 0; i < size; i++) bytes.at(offset + i) = static_cast<uint8_t>(word >> (8 * (size - i - 1)));
}

static uint32_t get(const std::vector<uint8_t>& bytes, uint32_t offset)
{
	uint32_t word = 0;
	for(uint32_t i = 0; i < 4; i++) word = (word << 8) | bytes.at(offset + i);
	return word;
}

static std::vector<uint8_t> packet(uint8_t rawVariant, uint16_t base, const std::vector<Record>& records)
{
	std::vector<uint8_t> bytes(8 + records.size() * 28);
	put(bytes, 0, (static_cast<uint32_t>(bytes.size() / 4 - 1) << 16) | (uint32_t(rawVariant) << 8) | 0x2C);
	put(bytes, 4, (static_cast<uint32_t>(records.size()) << 16) | base);
	for(uint32_t r = 0; r < records.size(); r++)
	{
		for(uint32_t i = 0; i < 6; i++) put(bytes, 8 + r * 28 + i * 4, records[r].words[i]);
		put(bytes, 8 + r * 28 + 24, records[r].weight, 2);
		put(bytes, 8 + r * 28 + 26, records[r].destination, 2);
	}
	return bytes;
}

static void require(bool value)
{
	if(!value) throw std::runtime_error("Weighted transform fixture failed.");
}

static void fixtures()
{
	SA2::ModelVertexMatrixFloat32 matrix{{0x3F800000,0,0,0,0x3F800000,0,0,0,0x3F800000,0,0,0}};
	std::vector<uint8_t> initial(160, 0xA5);
	for(uint32_t slot = 0; slot < 5; slot++) for(uint32_t i = 0; i < 6; i++) put(initial, slot * 32 + i * 4, 0x3F800000);
	Record twos{{0x40000000,0x40000000,0x40000000,0x40000000,0x40000000,0x40000000},256,1};
	uint32_t preserved = 0, rejected = 0;
	auto reject = [&](const std::vector<uint8_t>& bytes, uint64_t offset, const SA2::ModelVertexMatrixFloat32& m, const std::vector<uint8_t>& scratch) {
		try { SA2::transformModelWeightedVertexPacketFloat32(bytes, offset, m, scratch); }
		catch(const std::runtime_error&) { rejected++; return; }
		throw std::runtime_error("Expected host rejection.");
	};
	/* Original mode, destination and untouched-byte quirks are checked separately from the independent arithmetic oracle. */
	auto bytes = packet(0, 2, {twos});
	auto result = SA2::transformModelWeightedVertexPacketFloat32(bytes, 0, matrix, initial);
	require(result.baseScratchIndex == 2 && result.recordCount == 1 && result.variant == 0);
	for(uint32_t i = 0; i < 6; i++) require(get(result.scratch, 96 + i * 4) == 0x40000000);
	for(uint32_t i = 0; i < initial.size(); i++) if(i < 96 || i >= 120) require(result.scratch[i] == initial[i]);
	preserved++;
	Record half = twos; half.weight = 128;
	for(uint8_t mode : std::array<uint8_t,4>{1,2,127,129})
	{
		auto repeated = SA2::transformModelWeightedVertexPacketFloat32(packet(mode,0,{half,half}),0,matrix,initial);
		for(uint32_t i = 0; i < 6; i++) require(get(repeated.scratch,32+i*4) == 0x40400000);
		require(repeated.variant == (mode & 127));
		preserved++;
	}
	auto overwrite = SA2::transformModelWeightedVertexPacketFloat32(packet(128,0,{half,half}),0,matrix,initial);
	for(uint32_t i = 0; i < 6; i++) require(get(overwrite.scratch,32+i*4) == 0x3F800000);
	preserved++;
	Record negative = twos; negative.weight = 0xFF80;
	auto signedResult = SA2::transformModelWeightedVertexPacketFloat32(packet(0,0,{negative}),0,matrix,initial);
	for(uint32_t i = 0; i < 6; i++) require(get(signedResult.scratch,32+i*4) == 0xBF800000);
	preserved++;
	auto nanOld = initial; for(uint32_t i = 0; i < 6; i++) put(nanOld,96+i*4,0x7FC00001);
	require(SA2::transformModelWeightedVertexPacketFloat32(bytes,0,matrix,nanOld).scratch == result.scratch);
	preserved++;
	Record zero = twos; zero.weight = 0;
	auto zeroed = SA2::transformModelWeightedVertexPacketFloat32(packet(0,0,{zero}),0,matrix,initial);
	for(uint32_t i = 0; i < 6; i++) require(get(zeroed.scratch,32+i*4) == 0);
	preserved++;
	auto prefix = bytes; prefix.insert(prefix.begin(),{1,2,3});
	require(SA2::transformModelWeightedVertexPacketFloat32(prefix,3,matrix,initial).scratch == result.scratch);
	preserved++;
	auto padded = bytes; padded.insert(padded.end(),{0x7F,0xC0,0,1});
	require(SA2::transformModelWeightedVertexPacketFloat32(padded,0,matrix,initial).scratch == result.scratch);
	preserved++;
	auto alias = packet(0,0,{twos}); alias.resize(160,0xA5); auto beforeAlias = alias;
	SA2::transformModelWeightedVertexPacketFloat32(alias,0,matrix,alias); require(alias == beforeAlias);
	preserved++;
	reject({},0,matrix,initial);
	reject(bytes,UINT64_MAX,matrix,initial);
	reject(bytes,1,matrix,initial);
	auto bad = bytes; bad[3] = 0x29; reject(bad,0,matrix,initial);
	bad = bytes; bad[0] = 0xFF; reject(bad,0,matrix,initial);
	bad = bytes; bad[1] = 0; reject(bad,0,matrix,initial);
	bad = bytes; bad[4] = 0; bad[5] = 0; reject(bad,0,matrix,initial);
	bad = bytes; bad.pop_back(); reject(bad,0,matrix,initial);
	reject(bytes,0,matrix,std::vector<uint8_t>(127));
	Record far = twos; far.destination = 0xFFFF; reject(packet(0,0xFFFF,{far}),0,matrix,initial);
	Record nanInput = twos; nanInput.words[0] = 0x7FC00001; reject(packet(0,0,{nanInput}),0,matrix,initial);
	Record infInput = twos; infInput.words[3] = 0x7F800000; reject(packet(0,0,{infInput}),0,matrix,initial);
	auto invalidMatrix = matrix; invalidMatrix.words[11] = 0xFF800000; reject(bytes,0,invalidMatrix,initial);
	reject(packet(1,2,{twos}),0,matrix,nanOld);
	auto infOld = initial; put(infOld,96,0x7F800000); reject(packet(2,2,{twos}),0,matrix,infOld);
	Record overflow = twos; overflow.words[0] = 0x7F7FFFFF; overflow.weight = 0x7FFF; reject(packet(0,0,{overflow}),0,matrix,initial);
	int rounding = std::fegetround(); require(std::fesetround(FE_DOWNWARD) == 0);
	reject(bytes,0,matrix,initial); require(std::fesetround(rounding) == 0);
	std::cout << "preserved=" << preserved << " rejected=" << rejected << "\n";
}

int main(int argc, char** argv)
{
	try
	{
		if(argc == 2 && std::string(argv[1]) == "--fixtures") { fixtures(); return 0; }
		if(argc != 7) throw std::runtime_error("Expected input, offset, matrix, initial scratch, output scratch, metadata.");
		auto input = load(argv[1]); auto initial = load(argv[4]);
		std::ifstream matrixFile(argv[3]); SA2::ModelVertexMatrixFloat32 matrix;
		std::string word;
		for(auto& value : matrix.words)
		{
			if(!(matrixFile >> word)) throw std::runtime_error("Matrix is truncated.");
			value = static_cast<uint32_t>(std::stoul(word,nullptr,16));
		}
		auto result = SA2::transformModelWeightedVertexPacketFloat32(input,std::stoull(argv[2],nullptr,0),matrix,initial);
		save(argv[5],result.scratch);
		std::ofstream metadata(argv[6]);
		metadata << result.baseScratchIndex << "," << result.recordCount << "," << uint32_t(result.variant) << "\n";
		return 0;
	}
	catch(const std::exception& error) { std::cerr << error.what() << "\n"; return 1; }
}
