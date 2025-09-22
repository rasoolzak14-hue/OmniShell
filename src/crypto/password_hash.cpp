#include "password_hash.h"
#include <string>
#include <functional>

// VERY SIMPLE, NOT SECURE — replace with Argon2/bcrypt later.
// Format: "stub$<salt>$<hash>"
namespace crypto {
    static const std::string SALT = "change-me";

    std::string hash_password(const std::string& password) {
        std::hash<std::string> h;
        size_t v = h(SALT + password);
        return "stub$" + SALT + "$" + std::to_string(v);
    }

    bool verify_password(const std::string& password, const std::string& stored_hash) {
        // expect "stub$SALT$VALUE"
        auto pos1 = stored_hash.find('$');
        if (pos1 == std::string::npos) return false;
        auto pos2 = stored_hash.find('$', pos1 + 1);
        if (pos2 == std::string::npos) return false;
        std::string salt = stored_hash.substr(pos1 + 1, pos2 - pos1 - 1);
        std::hash<std::string> h;
        size_t v = h(salt + password);
        return stored_hash == ("stub$" + salt + "$" + std::to_string(v));
    }

}
