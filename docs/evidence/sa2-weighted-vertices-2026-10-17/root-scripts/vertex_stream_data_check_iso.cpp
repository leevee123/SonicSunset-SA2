#define main weightedCheckMain
#include "weighted_data_check.cpp"
#undef main
#include "Importers/SA2/Prs.h"
#include "GCDisc.h"

static void streamFixtures()
{
	SA2::ModelVertexMatrixFloat32 matrix{{0x3F800000,0,0,0,0x3F800000,0,0,0,0x3F800000,0,0,0}};
	std::vector<uint8_t> initial(160,0xA5);
	for(uint32_t slot=0;slot<5;slot++) for(uint32_t i=0;i<6;i++) put(initial,slot*32+i*4,0x3F800000);
	uint32_t preserved=0,rejected=0;
	auto appendEnd=[](std::vector<uint8_t> bytes) { bytes.insert(bytes.end(),{0xFF,0xFF,0xFF,0xFF});return bytes; };
	auto reject=[&](const std::vector<uint8_t>& bytes,uint64_t offset) {
		try { SA2::transformModelVertexStreamFloat32(bytes,offset,matrix,initial,0xA5A50000,0xDEADBEEF); }
		catch(const std::runtime_error&) { rejected++;return; }
		throw std::runtime_error("Expected stream rejection.");
	};
	/* END does not consume info, matrix values or scratch; unknown four-byte packets read info overlapping the following header. */
	auto unused=matrix;unused.words.fill(0x7FC00001);
	auto end=SA2::transformModelVertexStreamFloat32({0xFF,0xFF,0xFF,0xFF},0,unused,initial,0xA5A50000,0xDEADBEEF);
	require(end.endOffset==4 && end.stateBits==0xA5A50000 && end.gqr1Word==0xDEADBEEF && end.scratch==initial);preserved++;
	auto opaque=SA2::transformModelVertexStreamFloat32({0,0,0,0,0xFF,0xFF,0xFF,0xFF},0,unused,initial,0x12345678,0x89ABCDEF);
	require(opaque.endOffset==8 && opaque.stateBits==0x12345678 && opaque.gqr1Word==0x89ABCDEF && opaque.scratch==initial);preserved++;
	std::vector<uint8_t> opaqueLarge{0,1,0,0x77,0x7F,0xC0,0,1,0,0,0,0xFF};
	require(SA2::transformModelVertexStreamFloat32(opaqueLarge,0,unused,initial,5,6).scratch==initial);preserved++;
	/* A packed-word packet then a weighted accumulation shares the copied scratch, preserving both state bits and packed tail bytes. */
	std::vector<uint8_t> combined(24);
	put(combined,0,0x00050023);put(combined,4,0x00010001);
	for(uint32_t i=0;i<3;i++) put(combined,8+i*4,0x40000000);
	put(combined,20,0x12345678);
	Record half{{0x40000000,0x40000000,0x40000000,0x40000000,0x40000000,0x40000000},128,1};
	auto weighted=packet(2,0,{half});combined.insert(combined.end(),weighted.begin(),weighted.end());combined=appendEnd(combined);
	auto processed=SA2::transformModelVertexStreamFloat32(combined,0,matrix,initial,0xA5A50000,0xDEADBEEF);
	require(processed.endOffset==combined.size() && processed.stateBits==0xA5A50003 && processed.gqr1Word==0x08070807);
	for(uint32_t i=0;i<3;i++) require(get(processed.scratch,32+i*4)==0x40400000);
	for(uint32_t i=3;i<6;i++) require(get(processed.scratch,32+i*4)==0x40000000);
	require(get(processed.scratch,56)==0x34567812 && get(processed.scratch,60)==get(initial,60));preserved++;
	auto prefix=combined;prefix.insert(prefix.begin(),{9,8,7});
	auto shifted=SA2::transformModelVertexStreamFloat32(prefix,3,matrix,initial,0xA5A50000,0xDEADBEEF);
	require(shifted.scratch==processed.scratch && shifted.endOffset==processed.endOffset+3);preserved++;
	std::vector<uint8_t> plain(32);put(plain,0,0x00070029);put(plain,4,0x00010000);
	for(uint32_t i=0;i<6;i++) put(plain,8+i*4,0x3F800000);
	auto noClobber=SA2::transformModelVertexStreamFloat32(appendEnd(plain),0,matrix,initial,7,0x76543210);
	require(noClobber.stateBits==7 && noClobber.gqr1Word==0x76543210);preserved++;
	reject({},0);reject(combined,UINT64_MAX);
	auto missing=combined;missing.resize(missing.size()-4);reject(missing,0);
	reject({0,0,0,0x77},0);
	reject({0,1,0,0x2A,0,0,0,0,0,0,0,0xFF},0);
	auto zero=packet(0,0,{});reject(appendEnd(zero),0);
	std::cout<<"preserved="<<preserved<<" rejected="<<rejected<<"\n";
}

int main(int argc,char** argv)
{
	try
	{
		if(argc==4 && std::string(argv[1])=="--extract")
		{
			auto disc=GameCube::openGCDisc(argv[2]);save(argv[3],SA2::readPrsFile(disc,"sonicmdl.prs"));return 0;
		}
		if(argc==2 && std::string(argv[1])=="--stream-fixtures") { streamFixtures();return 0; }
		if(argc==10 && std::string(argv[1])=="--stream")
		{
			auto input=load(argv[2]);auto initial=load(argv[5]);
			std::ifstream matrixFile(argv[4]);SA2::ModelVertexMatrixFloat32 matrix;std::string word;
			for(auto& value:matrix.words)
			{
				if(!(matrixFile>>word)) throw std::runtime_error("Matrix is truncated.");
				value=static_cast<uint32_t>(std::stoul(word,nullptr,16));
			}
			auto result=SA2::transformModelVertexStreamFloat32(input,std::stoull(argv[3],nullptr,0),matrix,initial,static_cast<uint32_t>(std::stoul(argv[6],nullptr,0)),static_cast<uint32_t>(std::stoul(argv[7],nullptr,0)));
			save(argv[8],result.scratch);std::ofstream metadata(argv[9]);
			metadata<<result.endOffset<<","<<result.stateBits<<","<<result.gqr1Word<<"\n";return 0;
		}
		return weightedCheckMain(argc,argv);
	}
	catch(const std::exception& error) { std::cerr<<error.what()<<"\n";return 1; }
}
