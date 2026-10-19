#include "SA2PalettePreview.h"
#include "Importers/GameCube/GCDisc.h"
#include "Importers/SA2/ChaoPalette.h"
#include "Importers/SA2/Gvm.h"
#include "Importers/SA2/Gvp.h"
#include "Graphics/Resources/Texture.h"
#include <glad/glad.h>
#include <GLFW/glfw3.h>
#include "imgui.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include <nlohmann/json.hpp>
#include <stb_image_write.h>
#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace SA2
{
struct PreviewFamily
{
	std::string label;
	uint8_t type;
	std::array<uint32_t, 3> textureEntries;
};

struct Preview
{
	std::array<ChaoPaletteBank, 39> banks;
	GvmArchive body;
	std::vector<PreviewFamily> families;
	std::vector<Graphics::Texture> textures;
	ChaoPalette palette;
	ChaoPaletteParameters parameters{2, 0.0f, 0.0f, 0.5f, 0.5f};
	size_t family = 0;
	ImVec2 familyButton, resetButton;
	std::array<ImVec2, 4> mixButtons;
	std::array<std::array<float, 4>, 3> imageRects;
	bool dirty = true;
};

/* This manifest is diagnostic content, not an original game format. Validate it before opening graphics. */
static Preview loadPreview(const char* discPath_, const char* manifestPath_)
{
	std::ifstream manifestFile(manifestPath_);
	if(!manifestFile) throw std::runtime_error("Cannot open the preview's PalettePreview.json.");
	nlohmann::json manifest;
	manifestFile >> manifest;
	if(manifest.at("version") != 1 || manifest.at("banks").size() != 39 || manifest.at("families").size() != 6)
		throw std::runtime_error("The preview manifest needs version 1, 39 banks and six families.");

	/* Restrict the diagnostic to the inspected retail revision before passing the image to the shared FST reader. */
	std::ifstream discHeader(discPath_, std::ios::binary);
	std::array<char, 8> identity{};
	discHeader.read(identity.data(), identity.size());
	if(!discHeader || std::string(identity.data(), 6) != "GSNE8P" || identity[6] != 0 || identity[7] != 0)
		throw std::runtime_error("Select an uncompressed Sonic Adventure 2 Battle USA revision 0 disc image (GSNE8P).");
	auto disc = GameCube::openGCDisc(discPath_);
	Preview preview;
	for(size_t i = 0; i < preview.banks.size(); i++)
		updateChaoPalette(preview.banks[i], readGvpFile(disc, manifest.at("banks").at(i).get<std::string>()));
	preview.body = readGvmPrsFile(disc, manifest.at("bodyArchive").get<std::string>());
	for(const auto& row : manifest.at("families"))
	{
		unsigned type = row.at("type").get<unsigned>();
		if(type > 255) throw std::runtime_error("A preview family type is outside a byte.");
		PreviewFamily family{row.at("label").get<std::string>(), static_cast<uint8_t>(type), row.at("textureEntries").get<std::array<uint32_t, 3>>()};
		ChaoPalette probe;
		if(!buildChaoPalette(probe, preview.banks, {family.type, 0.0f, 0.0f, 0.5f, 0.5f}))
			throw std::runtime_error("A preview family has an unsupported palette type.");
		for(uint32_t entry : family.textureEntries)
			if(entry >= preview.body.textures.size() || preview.body.textures[entry].format != 8)
				throw std::runtime_error("A preview family needs three valid C4 body texture entries.");
		preview.families.push_back(family);
	}
	return preview;
}

static void releaseTextures(Preview& rPreview_)
{
	for(auto& texture : rPreview_.textures)
	{
		if(texture.alive) texture.destroy();
		texture.alive = false;
	}
	rPreview_.textures.clear();
}

/* ChaoMain +0x1F1B8 supplies the entry triple; +0x1F2E4 supplies the three contiguous RGB565 groups. */
static void rebuildTextures(Preview& rPreview_)
{
	rPreview_.parameters.type = rPreview_.families[rPreview_.family].type;
	if(!buildChaoPalette(rPreview_.palette, rPreview_.banks, rPreview_.parameters))
		throw std::runtime_error("Cannot generate this family's palette.");
	releaseTextures(rPreview_);
	rPreview_.textures.reserve(3);
	for(uint32_t group = 0; group < 3; group++)
	{
		const auto& source = rPreview_.body.textures[rPreview_.families[rPreview_.family].textureEntries[group]];
		auto levels = decodeTexture(source, chaoPaletteGroupColors(rPreview_.palette, group));
		rPreview_.textures.emplace_back(source.width, source.height, 4);
		/* Nearest/clamp and RGBA8 are inspection choices. Original materials, sampling and frame color are unverified. */
		rPreview_.textures.back().createWithMipLevels(levels, GL_NEAREST, GL_NEAREST, GL_CLAMP_TO_EDGE, GL_CLAMP_TO_EDGE);
	}
	rPreview_.dirty = false;
}

static ImVec2 itemCenter()
{
	auto low = ImGui::GetItemRectMin();
	auto high = ImGui::GetItemRectMax();
	return {(low.x + high.x) * 0.5f, (low.y + high.y) * 0.5f};
}

static void resetPreview(Preview& rPreview_)
{
	rPreview_.family = 0;
	rPreview_.parameters = {rPreview_.families[0].type, 0.0f, 0.0f, 0.5f, 0.5f};
	rPreview_.dirty = true;
}

/* The field names are unknown: neutral labels avoid assigning gameplay meanings to the four original floats. */
static void drawPreview(Preview& rPreview_)
{
	const auto& io = ImGui::GetIO();
	ImGui::SetNextWindowPos({0.0f, 0.0f});
	ImGui::SetNextWindowSize(io.DisplaySize);
	ImGui::Begin("SA2 Chao texture preview", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);
	ImGui::TextUnformatted("SA2 Chao texture preview");
	ImGui::TextWrapped("Change family and mixes to recolor the original Chao body textures.");
	ImGui::TextDisabled("Texture preview. The 3D model and gameplay are still to come.");
	ImGui::Spacing();
	for(size_t i = 0; i < rPreview_.families.size(); i++)
	{
		if(i != 0) ImGui::SameLine();
		bool selected = i == rPreview_.family;
		if(selected) ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.15f, 0.45f, 0.65f, 1.0f));
		if(ImGui::Button(rPreview_.families[i].label.c_str(), {100.0f, 30.0f}))
		{
			rPreview_.family = i;
			rPreview_.dirty = true;
		}
		if(i == 1) rPreview_.familyButton = itemCenter();
		if(selected) ImGui::PopStyleColor();
	}
	ImGui::Spacing();
	std::array<float*, 4> values{&rPreview_.parameters.valueA8, &rPreview_.parameters.valueAC, &rPreview_.parameters.valueB0, &rPreview_.parameters.valueC0};
	const std::array<const char*, 4> labels{"Mix A", "Mix B", "Mix C", "Mix D"};
	for(size_t i = 0; i < values.size(); i++)
	{
		ImGui::BeginDisabled(i == 2 && rPreview_.families[rPreview_.family].type != 2);
		ImGui::SetNextItemWidth(500.0f);
		if(ImGui::SliderFloat(labels[i], values[i], -1.0f, 1.0f, "%.2f")) rPreview_.dirty = true;
		auto low = ImGui::GetItemRectMin();
		rPreview_.mixButtons[i] = {low.x + 400.0f, itemCenter().y};
		ImGui::EndDisabled();
	}
	ImGui::TextDisabled("Mix C is used by Family 1. Some combinations produce the same colors.");
	if(ImGui::Button("Reset", {100.0f, 28.0f})) resetPreview(rPreview_);
	rPreview_.resetButton = itemCenter();
	ImGui::SameLine();
	ImGui::TextDisabled("Close the window or press Escape to exit.");
	ImGui::Separator();
	if(rPreview_.dirty) rebuildTextures(rPreview_);

	/* Each texture is shown with precisely its own 16-color group, using the decoded top row at v=0. */
	float size = std::min(320.0f, (ImGui::GetContentRegionAvail().x - 32.0f) / 3.0f);
	for(uint32_t group = 0; group < 3; group++)
	{
		if(group != 0) ImGui::SameLine(0.0f, 16.0f);
		ImGui::BeginGroup();
		ImGui::Text("Texture %u", group + 1);
		ImGui::Image(static_cast<ImTextureID>(rPreview_.textures[group].textureId), {size, size});
		auto imageLow = ImGui::GetItemRectMin();
		auto imageHigh = ImGui::GetItemRectMax();
		rPreview_.imageRects[group] = {imageLow.x, imageLow.y, imageHigh.x, imageHigh.y};
		auto colors = chaoPaletteGroupColors(rPreview_.palette, group);
		auto origin = ImGui::GetCursorScreenPos();
		float swatch = size / 16.0f;
		for(size_t i = 0; i < colors.size(); i++)
		{
			const auto& color = colors[i];
			ImGui::GetWindowDrawList()->AddRectFilled({origin.x + static_cast<float>(i) * swatch, origin.y}, {origin.x + static_cast<float>(i + 1) * swatch, origin.y + 24.0f}, IM_COL32(color[0], color[1], color[2], color[3]));
		}
		ImGui::Dummy({size, 24.0f});
		ImGui::EndGroup();
	}
	ImGui::End();
}

/* The optional bounded check reads every uploaded level and compares it with the CPU decoder; it uses no game globals. */
static size_t checkTextures(const Preview& rPreview_)
{
	size_t bytes = 0;
	for(uint32_t group = 0; group < 3; group++)
	{
		const auto& source = rPreview_.body.textures[rPreview_.families[rPreview_.family].textureEntries[group]];
		auto levels = decodeTexture(source, chaoPaletteGroupColors(rPreview_.palette, group));
		glBindTexture(GL_TEXTURE_2D, rPreview_.textures[group].textureId);
		for(size_t level = 0; level < levels.size(); level++)
		{
			std::vector<uint8_t> actual(levels[level].pixels.size());
			glGetTexImage(GL_TEXTURE_2D, static_cast<GLint>(level), GL_RGBA, GL_UNSIGNED_BYTE, actual.data());
			if(actual != levels[level].pixels) throw std::runtime_error("Preview GPU readback differs from the decoded texture.");
			bytes += actual.size();
		}
	}
	return bytes;
}

/* Capture our own rendered back buffer, reversing GL's bottom-first rows for the PNG writer. */
static void saveFrame(GLFWwindow* pWindow_, const std::filesystem::path& path_)
{
	int width, height;
	glfwGetFramebufferSize(pWindow_, &width, &height);
	std::vector<uint8_t> pixels(static_cast<size_t>(width) * height * 4);
	glReadBuffer(GL_BACK);
	glReadPixels(0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE, pixels.data());
	for(int y = 0; y < height / 2; y++)
		std::swap_ranges(pixels.begin() + static_cast<size_t>(y) * width * 4, pixels.begin() + static_cast<size_t>(y + 1) * width * 4, pixels.begin() + static_cast<size_t>(height - y - 1) * width * 4);
	if(!stbi_write_png(path_.string().c_str(), width, height, 4, pixels.data(), width * 4))
		throw std::runtime_error("Cannot save the preview check frame.");
}

int runPalettePreview(int argc_, char** argv_)
{
	bool check = std::string(argv_[1]) == "--sa2-palette-preview-check";
	if(argc_ != (check ? 5 : 4))
	{
		std::fprintf(stderr, "Usage: SonicSunset --sa2-palette-preview <SA2.iso> <PalettePreview.json>\nCheck: SonicSunset --sa2-palette-preview-check <SA2.iso> <PalettePreview.json> <output folder>\n");
		return 1;
	}
	GLFWwindow* window = nullptr;
	bool glfwReady = false, glfwBackend = false, glBackend = false;
	Preview preview;
	int result = 0;
	bool checkFinished = !check;
	try
	{
		preview = loadPreview(argv_[2], argv_[3]);
		if(!glfwInit()) throw std::runtime_error("Cannot start GLFW for the preview.");
		glfwReady = true;
		glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 4);
		glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 5);
		glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
		glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GLFW_TRUE);
		glfwWindowHint(GLFW_VISIBLE, check ? GLFW_FALSE : GLFW_TRUE);
		window = glfwCreateWindow(1100, 760, "SA2 Chao texture preview", nullptr, nullptr);
		if(!window) throw std::runtime_error("The preview needs OpenGL 4.5 support.");
		glfwSetWindowSizeLimits(window, 900, 650, GLFW_DONT_CARE, GLFW_DONT_CARE);
		glfwMakeContextCurrent(window);
		if(!gladLoadGLLoader(reinterpret_cast<GLADloadproc>(glfwGetProcAddress)))
			throw std::runtime_error("Cannot load the preview's OpenGL functions.");
		glfwSwapInterval(check ? 0 : 1);
		IMGUI_CHECKVERSION();
		ImGui::CreateContext();
		ImGui::GetIO().IniFilename = nullptr;
		ImGui::StyleColorsDark();
		glfwBackend = ImGui_ImplGlfw_InitForOpenGL(window, true);
		glBackend = ImGui_ImplOpenGL3_Init("#version 450 core");
		if(!glfwBackend || !glBackend) throw std::runtime_error("Cannot initialize the preview controls.");

		std::filesystem::path output = check ? argv_[4] : "";
		nlohmann::json report{{"passed", true}, {"banks", preview.banks.size()}, {"bodyTextures", preview.body.textures.size()}, {"gpuBytesCompared", 0}, {"familyCases", 0}, {"controlChecks", nlohmann::json::array()}};
		/* Exercise all six manifest families before testing real ImGui button/slider events on the shared draw path. */
		if(check)
		{
			std::filesystem::create_directories(output);
			for(size_t family = 0; family < preview.families.size(); family++)
			{
				preview.family = family;
				rebuildTextures(preview);
				report["gpuBytesCompared"] = report["gpuBytesCompared"].get<size_t>() + checkTextures(preview);
				report["familyCases"] = family + 1;
			}
		}
		resetPreview(preview);
		rebuildTextures(preview);
		auto baseline = preview.palette.rgb565;
		auto previous = baseline;
		for(unsigned frame = 0; !glfwWindowShouldClose(window); frame++)
		{
			glfwPollEvents();
			if(glfwGetKey(window, GLFW_KEY_ESCAPE) == GLFW_PRESS) break;
			ImGui_ImplOpenGL3_NewFrame();
			ImGui_ImplGlfw_NewFrame();
			/* Synthetic events stay inside this optional hidden check and pass through the actual ImGui widgets. */
			if(check)
			{
				auto& io = ImGui::GetIO();
				io.AddFocusEvent(true);
				bool press = frame == 1 || frame == 4 || frame == 7 || frame == 10 || frame == 13 || frame == 16 || frame == 19;
				bool release = frame == 2 || frame == 5 || frame == 8 || frame == 11 || frame == 14 || frame == 17 || frame == 20;
				if(press)
				{
					ImVec2 point = frame == 1 ? preview.familyButton : frame == 4 ? preview.mixButtons[3] : frame == 10 ? preview.mixButtons[0] : frame == 13 ? preview.mixButtons[1] : frame == 16 ? preview.mixButtons[2] : preview.resetButton;
					io.AddMousePosEvent(point.x, point.y);
					io.AddMouseButtonEvent(0, true);
				}
				if(release) io.AddMouseButtonEvent(0, false);
			}
			ImGui::NewFrame();
			drawPreview(preview);
			ImGui::Render();
			int width, height;
			glfwGetFramebufferSize(window, &width, &height);
			glViewport(0, 0, width, height);
			glDisable(GL_FRAMEBUFFER_SRGB);
			glClearColor(0.07f, 0.08f, 0.10f, 1.0f);
			glClear(GL_COLOR_BUFFER_BIT);
			ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
			if(check && (frame == 0 || frame == 3 || frame == 6 || frame == 9 || frame == 12 || frame == 15 || frame == 18 || frame == 21))
			{
				bool reset = frame == 9 || frame == 21;
				if(frame == 3 && preview.family != 1) throw std::runtime_error("Family button check failed.");
				if(frame == 6 && preview.parameters.valueC0 == 0.5f) throw std::runtime_error("Mix D slider check failed.");
				if(frame == 12 && preview.parameters.valueA8 == 0.0f) throw std::runtime_error("Mix A slider check failed.");
				if(frame == 15 && preview.parameters.valueAC == 0.0f) throw std::runtime_error("Mix B slider check failed.");
				if(frame == 18 && preview.parameters.valueB0 == 0.5f) throw std::runtime_error("Mix C slider check failed.");
				if(reset && (preview.family != 0 || preview.parameters.valueA8 != 0.0f || preview.parameters.valueAC != 0.0f || preview.parameters.valueB0 != 0.5f || preview.parameters.valueC0 != 0.5f || preview.palette.rgb565 != baseline))
					throw std::runtime_error("Reset button check failed.");
				if(frame == 3 || frame == 6)
					if(preview.palette.rgb565 == previous) throw std::runtime_error("A checked control did not change the palette.");
				report["gpuBytesCompared"] = report["gpuBytesCompared"].get<size_t>() + checkTextures(preview);
				report["controlChecks"].push_back({{"frame", frame}, {"family", preview.family}, {"mixes", {preview.parameters.valueA8, preview.parameters.valueAC, preview.parameters.valueB0, preview.parameters.valueC0}}});
				previous = preview.palette.rgb565;
				if(frame == 0) saveFrame(window, output / "default.png");
				if(frame == 6) saveFrame(window, output / "changed.png");
				if(frame == 21)
				{
					saveFrame(window, output / "reset.png");
					if(glGetError() != GL_NO_ERROR) throw std::runtime_error("OpenGL error during the preview check.");
					report["renderer"] = reinterpret_cast<const char*>(glGetString(GL_RENDERER));
					report["textureRects"] = preview.imageRects;
					std::ofstream reportFile(output / "check.ai.json");
					reportFile << report.dump(2) << '\n';
					if(!reportFile) throw std::runtime_error("Cannot write the preview check report.");
					std::ofstream humanFile(output / "check.md");
					humanFile << "SA2 Chao texture preview check passed.\n\nLoaded " << preview.banks.size() << " real palette banks and " << preview.body.textures.size()
						<< " body textures. All six families uploaded correctly. The actual family button, four sliders and Reset responded to synthetic ImGui mouse events. Reset restored the original palette.\n\nCompared "
						<< report["gpuBytesCompared"].get<size_t>() << " GPU texture bytes with the verified CPU decoder. Saved default.png, changed.png and reset.png from this app's rendered back buffer.\n\nThis checks a texture diagnostic, not a retail game frame, model, animation or gameplay.\n";
					if(!humanFile) throw std::runtime_error("Cannot write the readable preview check report.");
					std::puts("SA2 preview check passed: six families, four sliders, family/reset buttons and GPU pixels.");
					checkFinished = true;
					break;
				}
			}
			glfwSwapBuffers(window);
			if(check && frame >= 24) throw std::runtime_error("Preview check exceeded its frame limit.");
		}
		if(!checkFinished) throw std::runtime_error("Preview check ended before its checks completed.");
	}
	catch(const std::exception& error)
	{
		std::fprintf(stderr, "SA2 preview: %s\n", error.what());
		result = 1;
	}
	/* Delete our GPU resources while the private context is alive, then unwind only the backends we initialized. */
	if(window) releaseTextures(preview);
	if(glBackend) ImGui_ImplOpenGL3_Shutdown();
	if(glfwBackend) ImGui_ImplGlfw_Shutdown();
	if(ImGui::GetCurrentContext()) ImGui::DestroyContext();
	if(window) glfwDestroyWindow(window);
	if(glfwReady) glfwTerminate();
	return result;
}
}
