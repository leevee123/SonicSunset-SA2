#define main transformCheckMain
#include "transform_data_check.cpp"
#undef main
#include "Importers/SA2/Prs.h"
#include "GCDisc.h"

int main(int argc, char** argv)
{
	if(argc == 4 && std::string(argv[1]) == "--extract")
	{
		try
		{
			auto disc = GameCube::openGCDisc(argv[2]);
			save(argv[3], SA2::readPrsFile(disc, "sonicmdl.prs"));
			return 0;
		}
		catch(const std::exception& error)
		{
			std::cerr << error.what() << "\n";
			return 1;
		}
	}
	return transformCheckMain(argc, argv);
}
