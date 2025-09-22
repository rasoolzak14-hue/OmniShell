#pragma once
#include <string>
#include <vector>
#include <unordered_map>   // NEW: for synonym maps
#include <optional>        // NEW: reserved for future use

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

    // Substring search over command/description (will use synonyms if loaded)
    std::vector<Command> search(const std::string& keyword) const;

    std::string currentProvider() const { return provider_; }

    // ===== NEW: synonyms support =====
    // Load "data/synonyms.json" (or any path). Safe to call once at startup.
    bool loadSynonyms(const std::string& path);

    // Tell the engine which provider's synonym bucket to use (e.g., "linux", "powershell").
    void setActiveProviderId(const std::string& id);

private:
    std::string provider_;
    std::vector<Command> commands_;

    // NEW: provider_id -> (normalized phrase -> canonical command)
    std::unordered_map<std::string,
        std::unordered_map<std::string, std::string>> synonyms_;

    // NEW: which provider is currently active for synonym expansion
    std::string activeProviderId_;
};
