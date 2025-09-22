#pragma once
#include <filesystem>
#include <string>

inline std::filesystem::path exe_dir(const char* argv0) {
    std::error_code ec;
    auto p = std::filesystem::weakly_canonical(std::filesystem::path(argv0), ec);
    return ec ? std::filesystem::current_path() : p.parent_path();
}

inline std::string data_path(const char* argv0, const std::string& filename) {
    return (exe_dir(argv0) / "data" / filename).string();
}
