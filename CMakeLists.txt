cmake_minimum_required(VERSION 4.0)

project(My_First_Project LANGUAGES CXX)

# ---- C++ standard ----
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- Executable & sources ----
add_executable(My_First_Project
        src/main.cpp
        src/linux.cpp
        src/powershell.cpp
)

# So headers like "commands.h" in src/ are found
target_include_directories(My_First_Project PRIVATE src)

# ---- nlohmann/json (header-only) ----
include(FetchContent)
FetchContent_Declare(
        json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(json)
target_link_libraries(My_First_Project PRIVATE nlohmann_json::nlohmann_json)

# ---- Copy data/ next to the built binary (Windows-friendly run) ----
# After build, you'll have: <build>/My_First_Project.exe and <build>/data/*
add_custom_command(TARGET My_First_Project POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/data
        $<TARGET_FILE_DIR:My_First_Project>/data
        COMMENT "Copying data/ to output directory"
)
