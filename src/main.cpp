// src/main.cpp
#include "engine.h"
#include "auth/auth_service.h"
#include "auth/store.h"
#include "path_utils.h" // if your file is named path_util.h, change include accordingly

#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include <memory>

// factory from store_json.cpp
std::unique_ptr<ICredentialStore> make_json_store(const std::string& path);

// ----- Helpers for interaction -----

static void show_all(const std::vector<Command>& cmds, const std::string& title) {
    std::cout << "\n=== " << title << " ===\n";
    for (const auto& c : cmds) {
        std::cout << c.command << " -> " << c.description << '\n';
    }
    std::cout << std::endl;
}

static void browse_by_number(const std::vector<Command>& cmds, const std::string& title) {
    if (cmds.empty()) {
        std::cout << "No commands to display.\n";
        return;
    }

    while (true) {
        std::cout << "\n=== " << title << " (Browse) ===\n";
        for (size_t i = 0; i < cmds.size(); ++i) {
            std::cout << (i + 1) << ". " << cmds[i].command << '\n';
        }
        std::cout << "0. Back\n";
        std::cout << "Choose a command number: ";

        int choice = -1;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid input.\n";
            continue;
        }
        if (choice == 0) break;
        if (choice < 1 || static_cast<size_t>(choice) > cmds.size()) {
            std::cout << "Out of range.\n";
            continue;
        }

        const auto& c = cmds[static_cast<size_t>(choice) - 1];
        std::cout << "\n" << c.command << " -> " << c.description << "\n";
    }
}

static void search_commands(const std::vector<Command>& cmds, const std::string& title) {
    // consume leftover newline if any
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::cout << "\n=== " << title << " (Search) ===\n";
    std::cout << "Type a keyword to search (or just press Enter to go back): ";

    std::string keyword;
    while (true) {
        std::getline(std::cin, keyword);
        if (keyword.empty()) break;

        std::cout << "\nResults for \"" << keyword << "\":\n";
        bool found = false;
        for (const auto& c : cmds) {
            if (c.command.find(keyword) != std::string::npos ||
                c.description.find(keyword) != std::string::npos) {
                std::cout << " - " << c.command << " -> " << c.description << '\n';
                found = true;
            }
        }
        if (!found) std::cout << " (no matches)\n";

        std::cout << "\nEnter another keyword (or press Enter to go back): ";
    }
}

int main(int argc, char** argv) {
    // --- Auth bootstrap (JSON-backed) ---
    std::string usersFile = data_path(argv[0], "users.json");
    std::string err;
    AuthService auth(make_json_store(usersFile));
    if (!auth.init(&err)) {
        std::cout << "Auth init failed: " << err << "\n";
    }

    while (!auth.is_logged_in()) {
        std::cout << "=== CommandApp ===\n";
        std::cout << "1) Login\n";
        std::cout << "2) Register\n";
        std::cout << "3) Continue as Guest\n";
        std::cout << "0) Exit\n";
        std::cout << "Choice: ";

        int c = -1;
        if (!(std::cin >> c)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }
        if (c == 0) return 0;

        if (c == 1) {
            std::string u, p;
            std::cout << "Username: "; std::cin >> u;
            std::cout << "Password: "; std::cin >> p; // TODO: no-echo later
            if (!auth.login(u, p, &err)) std::cout << "Login failed: " << err << "\n";
        } else if (c == 2) {
            std::string u, p;
            std::cout << "New username: "; std::cin >> u;
            std::cout << "New password: "; std::cin >> p;
            if (!auth.register_user(u, p, &err)) std::cout << "Register failed: " << err << "\n";
            else std::cout << "Registered. You can login now.\n";
        } else if (c == 3) {
            break; // guest mode
        } else {
            std::cout << "Invalid.\n";
        }
    }

    Engine engine;
    engine.loadSynonyms(data_path(argv[0], "synonyms.json"));

    while (true) {
        std::cout << "=== CommandApp";
        if (auth.is_logged_in()) std::cout << " (" << auth.current_username() << ")";
        std::cout << " ===\n";
        std::cout << "Select provider:\n";
        std::cout << "  1. Linux\n";
        std::cout << "  2. PowerShell\n";
        std::cout << "  3. Python\n";
        std::cout << "  0. Exit\n";
        std::cout << "Choice: ";

        int provider = -1;
        if (!(std::cin >> provider)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid input.\n\n";
            continue;
        }
        if (provider == 0) break;
        if (provider != 1 && provider != 2 && provider != 3) {
            std::cout << "Invalid choice.\n\n";
            continue;
        }

        std::string title, dataFile, providerId;
        if (provider == 1)      { title = "Linux Commands";      dataFile = data_path(argv[0], "linux_commands.json");      providerId = "linux"; }
        else if (provider == 2) { title = "PowerShell Commands"; dataFile = data_path(argv[0], "powershell_commands.json"); providerId = "powershell"; }
        else                    { title = "Python Commands";    dataFile = data_path(argv[0], "python_commands.json");     providerId = "python"; }

        if (!engine.loadProvider(title, dataFile)) {
            std::cout << "No commands loaded (check your JSON path).\n\n";
            continue;
        }
        engine.setActiveProviderId(providerId);

        while (true) {
            std::cout << "\n=== " << title << " ===\n";
            std::cout << "  1. View all\n";
            std::cout << "  2. Browse by number\n";
            std::cout << "  3. Search by keyword\n";
            std::cout << "  0. Back\n";
            std::cout << "Choice: ";

            int mode = -1;
            if (!(std::cin >> mode)) {
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                std::cout << "Invalid input.\n";
                continue;
            }

            if (mode == 0) break;
            if (mode == 1) {
                show_all(engine.listAll(), title);
            } else if (mode == 2) {
                browse_by_number(engine.listAll(), title);
            } else if (mode == 3) {
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                std::cout << "Keyword: ";
                std::string k; std::getline(std::cin, k);
                auto results = engine.search(k);
                if (results.empty()) {
                    std::cout << "(no matches)\n";
                } else {
                    show_all(results, title + " (Search Results)");
                }
            } else {
                std::cout << "Invalid choice.\n";
            }
        }
        std::cout << '\n';
    }

    return 0;
}
