// src/main.cpp
#include "commands.h"
#include <iostream>
#include <string>
#include <vector>
#include <limits>


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

// Loaders wrapper: returns (title, commands)
static std::pair<std::string, std::vector<Command>>
load_provider(int providerChoice) {
    // Adjust these paths if your run directory differs.
    if (providerChoice == 1) {
        return { "Linux Commands", load_linux_commands("../data/linux_commands.json") };
    } else if (providerChoice == 2) {
        return { "PowerShell Commands", load_ps_commands("../data/powershell_commands.json") };
    }
    return { "", {} };
}

int main() {
    while (true) {
        std::cout << "=== CommandApp ===\n";
        std::cout << "Select provider:\n";
        std::cout << "  1. Linux\n";
        std::cout << "  2. PowerShell\n";
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
        if (provider != 1 && provider != 2) {
            std::cout << "Invalid choice.\n\n";
            continue;
        }

        auto [title, cmds] = load_provider(provider);
        if (cmds.empty()) {
            std::cout << "No commands loaded (check your JSON path).\n\n";
            continue;
        }

        // Secondary menu for how to view commands
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
                show_all(cmds, title);
            } else if (mode == 2) {
                browse_by_number(cmds, title);
            } else if (mode == 3) {
                search_commands(cmds, title);
            } else {
                std::cout << "Invalid choice.\n";
            }
        }
        std::cout << '\n';
    }

    return 0;
}
