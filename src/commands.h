#pragma once
#include <string>
#include <vector>

struct Command {
    std::string command;
    std::string description;
};

// Implemented in linux.cpp
std::vector<Command> load_linux_commands(const std::string& filepath);
void show_linux_commands(const std::vector<Command>& cmds);

// Implemented in powershell.cpp
std::vector<Command> load_ps_commands(const std::string& filepath);
void show_ps_commands(const std::vector<Command>& cmds);
