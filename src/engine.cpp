// src/engine.cpp
#include "engine.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <unordered_set>

// ---------- small helpers ----------
static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

// normalize: lowercase, trim, collapse internal whitespace
static std::string norm(std::string s) {
    s = lower(s);

    auto isspace2 = [](unsigned char c){ return std::isspace(c) != 0; };

    // trim left
    while (!s.empty() && isspace2(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    // trim right
    while (!s.empty() && isspace2(static_cast<unsigned char>(s.back()))) s.pop_back();

    // collapse internal spaces
    std::string out; out.reserve(s.size());
    bool in_space = false;
    for (unsigned char c : s) {
        if (isspace2(c)) {
            if (!in_space) { out.push_back(' '); in_space = true; }
        } else {
            out.push_back(static_cast<char>(c));
            in_space = false;
        }
    }
    return out;
}

// ---------- existing JSON loader (unchanged behavior) ----------
static std::vector<Command> load_from_json(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file) return {};
    nlohmann::json j;
    file >> j;

    if (!j.is_array()) return {};

    std::vector<Command> out;
    out.reserve(j.size());
    for (const auto& item : j) {
        if (!item.is_object()) continue;
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

// ---------- NEW: load synonyms from a JSON object ----------
bool Engine::loadSynonyms(const std::string& path) {
    std::ifstream f(path);
    if (!f) return false;

    nlohmann::json j;
    try { f >> j; } catch (...) { return false; }
    if (!j.is_object()) return false;

    synonyms_.clear();

    // Expecting:
    // {
    //   "PowerShell": { "remove item": "Remove-Item", ... },
    //   "Linux":      { "remove item": "rm", ... }
    // }
    for (auto itProv = j.begin(); itProv != j.end(); ++itProv) {
        const std::string provId = norm(itProv.key()); // normalize id (e.g., "linux")
        const auto& bucket = itProv.value();
        if (!bucket.is_object()) continue;

        for (auto it = bucket.begin(); it != bucket.end(); ++it) {
            const std::string phrase = norm(it.key()); // normalize phrase: "remove item"
            if (!it.value().is_string()) continue;
            const std::string canonical = it.value().get<std::string>(); // e.g., "rm"
            synonyms_[provId][phrase] = canonical;
        }
    }
    return true;
}

// ---------- NEW: set active provider id used for synonym lookup ----------
void Engine::setActiveProviderId(const std::string& id) {
    activeProviderId_ = norm(id);
}

// ---------- UPDATED: search with case-insensitive matching + synonyms ----------
std::vector<Command> Engine::search(const std::string& keyword) const {
    if (keyword.empty()) return commands_;

    // Build query terms: original + (optional) canonical term from synonyms
    std::vector<std::string> terms;
    terms.push_back(keyword);

    if (!activeProviderId_.empty()) {
        auto itProv = synonyms_.find(activeProviderId_);
        if (itProv != synonyms_.end()) {
            auto it = itProv->second.find(norm(keyword));
            if (it != itProv->second.end()) {
                terms.push_back(it->second); // add canonical command like "rm" or "Remove-Item"
            }
        }
    }

    // Deduplicate normalized terms
    std::unordered_set<std::string> seen;
    std::vector<std::string> unique;
    unique.reserve(terms.size());
    for (auto& t : terms) {
        auto nt = norm(t);
        if (seen.insert(nt).second) unique.push_back(t);
    }

    // Case-insensitive contains match against command and description
    std::vector<Command> results;
    results.reserve(commands_.size());
    for (const auto& c : commands_) {
        const std::string cmdL  = lower(c.command);
        const std::string descL = lower(c.description);

        bool match = false;
        for (const auto& t : unique) {
            const std::string q = lower(t);
            if (cmdL.find(q) != std::string::npos || descL.find(q) != std::string::npos) {
                match = true;
                break;
            }
        }
        if (match) results.push_back(c);
    }

    return results;
}
