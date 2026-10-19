#include "Prs.h"
#include "Importers/STH2005/Prs.h"
#include "GCDisc.h"

namespace SA2
{
/*
SA2 Battle FUN_800d2684 uses the same PRS token rules and forward overlapping
copies as the existing decoder. Reuse it without changing Shadow's entry point.
See docs/SA2_PRS_REFERENCE.md for the function, assembly correction and validation.
*/
std::vector<uint8_t> decompressPrs(const std::vector<uint8_t>& rSrc_)
{
	return STH2005::decompressPrs(rSrc_);
}

/* A PRS file is one stream; read its disc bytes before decoding the payload. */
std::vector<uint8_t> readPrsFile(GameCube::GCDisc& rDisc_, const std::string& path_)
{
	return decompressPrs(rDisc_.readFile(path_));
}
}
