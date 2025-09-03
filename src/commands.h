#pragma once
#include <string>
#include <vector>

struct Command {
    std::string command;
    std::string description;
};

// Linux
std::vector<Command> load_linux_commands(const std::string& filepath);
void show_linux_commands(const std::vector<Command>& cmds);

// PowerShell
std::vector<Command> load_ps_commands(const std::string& filepath);
void show_ps_commands(const std::vector<Command>& cmds);
