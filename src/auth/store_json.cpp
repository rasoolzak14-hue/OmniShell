#include "store.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <mutex>

class JsonStore : public ICredentialStore {
public:
    explicit JsonStore(std::string path) : path_(std::move(path)) {}

    bool init(std::string* err = nullptr) override {
        std::scoped_lock lock(mu_);
        namespace fs = std::filesystem;
        try {
            if (!fs::exists(fs::path(path_).parent_path()))
                fs::create_directories(fs::path(path_).parent_path());

            if (!fs::exists(path_)) {
                nlohmann::json j = {{"users", nlohmann::json::array()}, {"next_id", 1}};
                std::ofstream out(path_);
                out << j.dump(2);
            }
            return true;
        } catch (const std::exception& e) {
            if (err) *err = e.what();
            return false;
        }
    }

    bool create_user(const std::string& username,
                     const std::string& password_hash,
                     std::string* err = nullptr) override {
        std::scoped_lock lock(mu_);
        try {
            nlohmann::json j = load();
            // uniqueness check
            for (const auto& u : j["users"]) {
                if (u.value("username", "") == username) {
                    if (err) *err = "Username already exists";
                    return false;
                }
            }
            int id = j.value("next_id", 1);
            nlohmann::json rec = {
                {"id", id},
                {"username", username},
                {"password_hash", password_hash},
                {"created_at", iso_now_utc()},
                {"last_login", nullptr}
            };
            j["users"].push_back(rec);
            j["next_id"] = id + 1;
            save(j);
            return true;
        } catch (const std::exception& e) {
            if (err) *err = e.what();
            return false;
        }
    }

    std::optional<UserRecord> find_user(const std::string& username,
                                        std::string* err = nullptr) override {
        std::scoped_lock lock(mu_);
        try {
            nlohmann::json j = load();
            for (const auto& u : j["users"]) {
                if (u.value("username", "") == username) {
                    UserRecord r;
                    r.id = u.value("id", 0);
                    r.username = u.value("username", "");
                    r.password_hash = u.value("password_hash", "");
                    r.created_at = u.value("created_at", "");
                    if (!u["last_login"].is_null())
                        r.last_login = u.value("last_login", "");
                    return r;
                }
            }
            return std::nullopt;
        } catch (const std::exception& e) {
            if (err) *err = e.what();
            return std::nullopt;
        }
    }

    bool update_last_login(int user_id,
                           const std::string& iso_ts,
                           std::string* err = nullptr) override {
        std::scoped_lock lock(mu_);
        try {
            nlohmann::json j = load();
            for (auto& u : j["users"]) {
                if (u.value("id", 0) == user_id) {
                    u["last_login"] = iso_ts;
                    save(j);
                    return true;
                }
            }
            if (err) *err = "User id not found";
            return false;
        } catch (const std::exception& e) {
            if (err) *err = e.what();
            return false;
        }
    }

private:
    std::string path_;
    std::mutex mu_;

    nlohmann::json load() {
        std::ifstream in(path_);
        nlohmann::json j;
        in >> j;
        if (!j.contains("users")) j["users"] = nlohmann::json::array();
        if (!j.contains("next_id")) j["next_id"] = 1;
        return j;
    }

    void save(const nlohmann::json& j) {
        std::ofstream out(path_);
        out << j.dump(2);
    }

    static std::string iso_now_utc() {
        using namespace std::chrono;
        auto now = time_point_cast<seconds>(system_clock::now());
        std::time_t t = system_clock::to_time_t(now);
        std::tm tm{};
    #if defined(_WIN32)
        gmtime_s(&tm, &t);
    #else
        gmtime_r(&t, &tm);
    #endif
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return std::string(buf);
    }
};

// Factory you can use from main.cpp
std::unique_ptr<ICredentialStore> make_json_store(const std::string& path) {
    return std::unique_ptr<ICredentialStore>(new JsonStore(path));
}
