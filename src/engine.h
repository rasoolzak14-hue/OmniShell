#pragma once
#include <string>
#include <vector>

struct Command {
    std::string command;
    std::string description;
};

class Engine {
public:
    // Loads a provider's command list from a data file path.
    // provider: "Linux" or "PowerShell" (used for display/state only)
    // path: e.g. "data/linux_commands.json"
    bool loadProvider(const std::string& provider, const std::string& path);

    // Returns all commands currently loaded
    const std::vector<Command>& listAll() const { return commands_; }

    // Substring search over command/description
    std::vector<Command> search(const std::string& keyword) const;

    std::string currentProvider() const { return provider_; }

private:
    std::string provider_;
    std::vector<Command> commands_;
};