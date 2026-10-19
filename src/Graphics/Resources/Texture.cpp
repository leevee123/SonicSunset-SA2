#include "Texture.h"
#include <algorithm>
#include <array>
#include <utility>

namespace Graphics 
{	
Texture::Texture(uint32_t width_, uint32_t height_, uint32_t channels_) : width(width_), height(height_), channels(channels_)
{
	pixels.resize(static_cast<size_t>(width_) * height_ * channels_);
}

void Texture::setPixelBatch(void* data_, uint32_t dstOffset_, uint32_t size_)
{
	std::memcpy(this->pixels.data() + dstOffset_, data_, size_); 	
}

/*
Gives every fully transparent texel the color of its opaque neighbors, spreading outwards one texel per pass. The importers
store such texels as transparent black (CMPR), which mip generation and linear filtering would blend into the edge of the
visible part as a dark fringe. Alpha stays 0, so the texel is still transparent. Expects 4 channels.
*/
static void bleedTransparentColor(std::vector<unsigned char>& rPixels_, uint32_t width_, uint32_t height_)
{
	size_t count = static_cast<size_t>(width_) * height_;
	std::vector<char> known(count);
	size_t unknown = 0;
	for(size_t i = 0; i < count; i++)
	{
		known[i] = rPixels_[i * 4 + 3] != 0;
		if(!known[i]) unknown++;
	}
	if(unknown == 0 || unknown == count) return;

	/*
	Only the texels next to a texel that became known in the last pass can get a color in this one, so each pass looks at that frontier instead of the whole image; a texel gets the
	average of the neighbors known when the pass started, as a full scan would give. queued marks the texels already in the next frontier.
	*/
	auto forNeighbors = [&](size_t index_, auto&& rAction_)
	{
		int x = static_cast<int>(index_ % width_);
		int y = static_cast<int>(index_ / width_);
		for(int dy = -1; dy <= 1; dy++)
		{
			for(int dx = -1; dx <= 1; dx++)
			{
				int nx = x + dx;
				int ny = y + dy;
				if(nx < 0 || ny < 0 || nx >= static_cast<int>(width_) || ny >= static_cast<int>(height_)) continue;
				rAction_(static_cast<size_t>(ny) * width_ + nx);
			}
		}
	};
	std::vector<char> queued(count, 0);
	std::vector<size_t> frontier;
	for(size_t i = 0; i < count; i++)
	{
		if(known[i]) continue;
		bool touches = false;
		forNeighbors(i, [&](size_t n_) { touches = touches || known[n_]; });
		if(touches)
		{
			frontier.push_back(i);
			queued[i] = 1;
		}
	}

	while(!frontier.empty())
	{
		std::vector<std::pair<size_t, std::array<unsigned char, 3>>> resolved;
		for(size_t index : frontier)
		{
			unsigned sum[3] = {0, 0, 0};
			unsigned neighbors = 0;
			forNeighbors(index, [&](size_t n_)
			{
				if(!known[n_]) return;
				for(int c = 0; c < 3; c++) sum[c] += rPixels_[n_ * 4 + c];
				neighbors++;
			});
			resolved.push_back({index, {static_cast<unsigned char>(sum[0] / neighbors), static_cast<unsigned char>(sum[1] / neighbors), static_cast<unsigned char>(sum[2] / neighbors)}});
		}
		frontier.clear();
		for(const auto& rPixel : resolved)
		{
			std::copy(rPixel.second.begin(), rPixel.second.end(), rPixels_.begin() + rPixel.first * 4);
			known[rPixel.first] = 1;
		}
		for(const auto& rPixel : resolved)
		{
			forNeighbors(rPixel.first, [&](size_t n_)
			{
				if(known[n_] || queued[n_]) return;
				queued[n_] = 1;
				frontier.push_back(n_);
			});
		}
	}
}

void Texture::create()
{
	if (pixels.empty()) {
    	throw std::runtime_error("Failed to load texture!");
	}
	//std::cout << width;

	/*
	OpenGL's 4.3 feature to create read/write(in shaders) textures, instead of read only: 
	glTexStorage2D(GL_TEXTURE_2D, 1, GL_RGBA8, width, height);
	glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
	
	In shader: 
	layout(rgba8, binding = 0) uniform image2D uMaskImage;

	void main() {
		ivec2 coord = ivec2(gl_FragCoord.xy);
		imageStore(uMaskImage, coord, vec4(1.0, 0.0, 0.0, 1.0)); // Write a red pixel
	}

	*/

	if(this->mipmaps && this->channels == 4)
	{
		bleedTransparentColor(this->pixels, this->width, this->height);
	}

	// Create and Bind texture in memory
	glGenTextures(1, &textureId);
	glBindTexture(GL_TEXTURE_2D, textureId);

	// Now set parameters:
	// glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_BORDER); // Stretch texture to fit a quad 
	// glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_BORDER);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, this->wrap);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, this->wrap);
	/*
	With mipmaps the minification filter also picks the level, keeping the texture's own filter between texels:
	linear blends the two nearest levels, nearest takes the nearest level. Magnification is unchanged.
	*/
	GLint minFilter = this->filter;
	if(this->mipmaps)
	{
		minFilter = this->filter == GL_NEAREST ? GL_NEAREST_MIPMAP_NEAREST : GL_LINEAR_MIPMAP_LINEAR;
	}
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, minFilter);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, this->filter);

	// Texture upload:
glTexImage2D(
    GL_TEXTURE_2D,
    0,
    GL_SRGB8_ALPHA8,   
    this->width,
    this->height,
    0,
    GL_RGBA,
    GL_UNSIGNED_BYTE,
    this->pixels.data()
);

	/* The whole chain is generated from level 0 (the sRGB texture is filtered in linear space by the driver). */
	if(this->mipmaps) glGenerateMipmap(GL_TEXTURE_2D);

	this->pixels.clear(); 

	this->alive = true; 
}

/* Validate the whole supplied chain before creating a GL object; an invalid input leaves GPU state untouched. */
void Texture::createWithMipLevels(const std::vector<TextureMip>& rLevels_, GLint minFilter_, GLint magFilter_, GLint wrapS_, GLint wrapT_)
{
	if(this->alive || this->channels != 4 || rLevels_.empty() || this->width == 0 || this->height == 0)
	{
		throw std::runtime_error("Texture: invalid supplied mip chain or texture is already alive.");
	}
	uint32_t expectedWidth = this->width, expectedHeight = this->height;
	for(size_t i = 0; i < rLevels_.size(); i++)
	{
		const auto& level = rLevels_[i];
		if(level.width != expectedWidth || level.height != expectedHeight ||
			level.pixels.size() != uint64_t(expectedWidth) * expectedHeight * 4 ||
			(i != 0 && rLevels_[i - 1].width == 1 && rLevels_[i - 1].height == 1))
		{
			throw std::runtime_error("Texture: supplied mip dimensions or RGBA8 byte count are invalid.");
		}
		expectedWidth = std::max(1u, expectedWidth >> 1);
		expectedHeight = std::max(1u, expectedHeight >> 1);
	}
	bool minValid = minFilter_ == GL_NEAREST || minFilter_ == GL_LINEAR || minFilter_ == GL_NEAREST_MIPMAP_NEAREST ||
		minFilter_ == GL_LINEAR_MIPMAP_NEAREST || minFilter_ == GL_NEAREST_MIPMAP_LINEAR || minFilter_ == GL_LINEAR_MIPMAP_LINEAR;
	auto wrapValid = [](GLint value_) { return value_ == GL_CLAMP_TO_EDGE || value_ == GL_REPEAT || value_ == GL_MIRRORED_REPEAT; };
	if(!minValid || (magFilter_ != GL_NEAREST && magFilter_ != GL_LINEAR) || !wrapValid(wrapS_) || !wrapValid(wrapT_))
	{
		throw std::runtime_error("Texture: invalid explicit mip sampling settings.");
	}
	GLint maxSize;
	glGetIntegerv(GL_MAX_TEXTURE_SIZE, &maxSize);
	if(this->width > static_cast<uint32_t>(maxSize) || this->height > static_cast<uint32_t>(maxSize))
	{
		throw std::runtime_error("Texture: supplied image exceeds the GPU texture size limit.");
	}

	/* Caller unpack state may describe a buffer/strided image. Supply tightly packed CPU pixels and restore that state. */
	GLint previousTexture, previousBuffer, alignment, rowLength, skipRows, skipPixels;
	glGetIntegerv(GL_TEXTURE_BINDING_2D, &previousTexture);
	glGetIntegerv(GL_PIXEL_UNPACK_BUFFER_BINDING, &previousBuffer);
	glGetIntegerv(GL_UNPACK_ALIGNMENT, &alignment);
	glGetIntegerv(GL_UNPACK_ROW_LENGTH, &rowLength);
	glGetIntegerv(GL_UNPACK_SKIP_ROWS, &skipRows);
	glGetIntegerv(GL_UNPACK_SKIP_PIXELS, &skipPixels);
	glBindBuffer(GL_PIXEL_UNPACK_BUFFER, 0);
	glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
	glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
	glPixelStorei(GL_UNPACK_SKIP_ROWS, 0);
	glPixelStorei(GL_UNPACK_SKIP_PIXELS, 0);
	glGenTextures(1, &this->textureId);
	glBindTexture(GL_TEXTURE_2D, this->textureId);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_BASE_LEVEL, 0);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAX_LEVEL, static_cast<GLint>(rLevels_.size() - 1));
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, minFilter_);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, magFilter_);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, wrapS_);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, wrapT_);

	/* GL_RGBA8 retains the supplied component bytes. Each original level is uploaded; the legacy create() path is unchanged. */
	for(size_t i = 0; i < rLevels_.size(); i++)
	{
		const auto& level = rLevels_[i];
		glTexImage2D(GL_TEXTURE_2D, static_cast<GLint>(i), GL_RGBA8, static_cast<GLsizei>(level.width), static_cast<GLsizei>(level.height),
			0, GL_RGBA, GL_UNSIGNED_BYTE, level.pixels.data());
	}
	glBindTexture(GL_TEXTURE_2D, previousTexture);
	glBindBuffer(GL_PIXEL_UNPACK_BUFFER, previousBuffer);
	glPixelStorei(GL_UNPACK_ALIGNMENT, alignment);
	glPixelStorei(GL_UNPACK_ROW_LENGTH, rowLength);
	glPixelStorei(GL_UNPACK_SKIP_ROWS, skipRows);
	glPixelStorei(GL_UNPACK_SKIP_PIXELS, skipPixels);
	this->appliedWrapS = wrapS_;
	this->appliedWrapT = wrapT_;
	this->filter = magFilter_;
	this->wrap = wrapS_;
	this->mipmaps = rLevels_.size() > 1;
	this->pixels.clear();
	this->alive = true;
}

void Texture::destroy()
{
	glDeleteTextures(1, &textureId);
}

void Texture::use()
{
	glBindTexture(GL_TEXTURE_2D, textureId);
}
}
