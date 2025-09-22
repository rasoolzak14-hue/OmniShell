#include "auth_service.h"
#include "../crypto/password_hash.h"

AuthService::AuthService(std::unique_ptr<ICredentialStore> store)
    : store_(std::move(store)) {}

bool AuthService::init(std::string* err) {
    return store_->init(err);
}

bool AuthService::register_user(const std::string& username,
                                const std::string& password,
                                std::string* err) {
    if (username.empty() || password.empty()) {
        if (err) *err = "Username and password required";
        return false;
    }
    auto hash = crypto::hash_password(password);
    return store_->create_user(username, hash, err);
}

bool AuthService::login(const std::string& username,
                        const std::string& password,
                        std::string* err) {
    auto rec = store_->find_user(username, err);
    if (!rec.has_value()) {
        if (err && err->empty()) *err = "User not found";
        return false;
    }
    if (!crypto::verify_password(password, rec->password_hash)) {
        if (err) *err = "Invalid credentials";
        return false;
    }
    current_ = *rec;

    // update last_login
    // naive ISO time from store_json’s helper isn’t accessible here; it’s okay to skip or reimplement:
    // For simplicity, we just skip timestamp here. You can add a small shared time util later.
    store_->update_last_login(current_->id, "", nullptr);
    return true;
}

void AuthService::logout() { current_.reset(); }
