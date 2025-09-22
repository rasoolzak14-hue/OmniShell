cmake_minimum_required(VERSION 3.20)

project(My_First_Project LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(My_First_Project
        src/main.cpp
        src/engine.cpp
        src/auth/store_json.cpp
        src/auth/auth_service.cpp
        src/crypto/password_hash.cpp
)

target_include_directories(My_First_Project PRIVATE src)

# nlohmann::json
include(FetchContent)
FetchContent_Declare(
        json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(json)
target_link_libraries(My_First_Project PRIVATE nlohmann_json::nlohmann_json)

# Copy data/ next to the built executable for dev runs
add_custom_command(TARGET My_First_Project POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/data
        $<TARGET_FILE_DIR:My_First_Project>/data
        COMMENT "Copying data/ to output directory"
)

#if (MINGW)
#    target_link_options(My_First_Project PRIVATE -static -static-libstdc++ -static-libgcc)
#endif()
