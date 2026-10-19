#pragma once
#include <cstdint>
#include <vector>

namespace Graphics
{
/* One already-decoded RGBA8 mip, top row first, kept independently of an OpenGL context. */
struct TextureMip
{
	uint32_t width, height;
	std::vector<uint8_t> pixels;
};
}
