#pragma once
#include <string>

namespace crypto {

    // NOTE: For production, prefer Argon2id or bcrypt via a proper library.
    // These functions are placeholders to wire the interface cleanly.

    std::string hash_password(const std::string& password);
    bool verify_password(const std::string& password, const std::string& stored_hash);

}
