#pragma once
#include <string>
#include <optional>

struct UserRecord {
    int id = 0;                        // simple auto id for JSON store
    std::string username;
    std::string password_hash;         // PHC-style or other hashed string
    std::string created_at;            // ISO 8601 (UTC)
    std::optional<std::string> last_login;
};

class ICredentialStore {
public:
    virtual ~ICredentialStore() = default;

    // Create storage if missing (create users.json with empty list)
    virtual bool init(std::string* err = nullptr) = 0;

    // Create a user (username must be unique)
    virtual bool create_user(const std::string& username,
                             const std::string& password_hash,
                             std::string* err = nullptr) = 0;

    // Find user by username
    virtual std::optional<UserRecord> find_user(const std::string& username,
                                                std::string* err = nullptr) = 0;

    // Update last_login timestamp
    virtual bool update_last_login(int user_id,
                                   const std::string& iso_ts,
                                   std::string* err = nullptr) = 0;
};
