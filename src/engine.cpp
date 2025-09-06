#include "engine.h"
#include <nlohmann/json.hpp>
#include <fstream>

static std::vector<Command> load_from_json(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file) return {};
    nlohmann::json j;
    file >> j;

    std::vector<Command> out;
    out.reserve(j.size());
    for (const auto& item : j) {
        out.push_back(Command{
            item.value("command", ""),
            item.value("description", "")
        });
    }
    return out;
}

bool Engine::loadProvider(const std::string& provider, const std::string& path) {
    auto cmds = load_from_json(path);
    if (cmds.empty()) return false;
    provider_ = provider;
    commands_ = std::move(cmds);
    return true;
}

std::vector<Command> Engine::search(const std::string& keyword) const {
    if (keyword.empty()) return commands_;
    std::vector<Command> results;
    for (const auto& c : commands_) {
        if (c.command.find(keyword) != std::string::npos ||
            c.description.find(keyword) != std::string::npos) {
            results.push_back(c);
            }
    }
    return results;
}
