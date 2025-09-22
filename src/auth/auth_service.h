#pragma once
#include "store.h"
#include <memory>
#include <optional>

class AuthService {
public:
    explicit AuthService(std::unique_ptr<ICredentialStore> store);

    bool init(std::string* err = nullptr);

    bool register_user(const std::string& username,
                       const std::string& password,
                       std::string* err = nullptr);

    bool login(const std::string& username,
               const std::string& password,
               std::string* err = nullptr);

    void logout();

    bool is_logged_in() const { return current_.has_value(); }
    std::string current_username() const { return current_ ? current_->username : ""; }
    int current_user_id() const { return current_ ? current_->id : 0; }

private:
    std::unique_ptr<ICredentialStore> store_;
    std::optional<UserRecord> current_;
};
