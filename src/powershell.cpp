#include "commands.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>

std::vector<Command> load_ps_commands(const std::string& filepath) { // <-- const std::string&
    std::ifstream file(filepath);
    if (!file) { std::cerr << "Error: Could not open " << filepath << "\n"; return {}; }

    nlohmann::json j; file >> j;
    std::vector<Command> cmds;
    cmds.reserve(j.size());
    for (const auto& item : j) {
        cmds.push_back(Command{ item.value("command",""), item.value("description","") });
    }
    return cmds;
}

void show_ps_commands(const std::vector<Command>& cmds) {
    std::cout << "=== PowerShell Commands ===\n";
    for (const auto& c : cmds) {
        std::cout << c.command << " -> " << c.description << "\n";
    }
}
