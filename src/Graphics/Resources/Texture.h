#pragma once 
#include <cstdint>
#include <glad/glad.h>
#include <stb_image.h>
#include <stdexcept>
#include <cstring> 
#include <vector>
#include "TextureMip.h"

namespace Graphics 
{
struct Texture 
{ 
	std::vector<unsigned char> pixels;
	uint32_t width, height, channels;
	GLuint textureId;
	GLint filter = GL_NEAREST;
	GLint wrap = GL_CLAMP_TO_EDGE;

	/* The wrap modes last set by a draw (SAInstance::draw sets them per material), 0 = not set yet: a draw only changes the state when the mode differs. */
	GLint appliedWrapS = 0;
	GLint appliedWrapT = 0;
	bool mipmaps = true;
	bool alive = false; 

	Texture(uint32_t width_, uint32_t height_, uint32_t channels_); 
	void setPixelBatch(void* data_, uint32_t dstOffset_, uint32_t size_);
	void create();
	/* Upload supplied RGBA8 mips unchanged. Sampling is explicit; no generated mips, color bleed or sRGB conversion. */
	void createWithMipLevels(const std::vector<TextureMip>& rLevels_, GLint minFilter_, GLint magFilter_, GLint wrapS_, GLint wrapT_);
	void destroy(); 
	void use(); 
}; 
}
