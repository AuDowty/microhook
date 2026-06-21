cmake_minimum_required(VERSION 3.20)
project(microhook VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "microhook is Windows-only")
endif()

add_library(microhook STATIC src/microhook.cpp)
target_include_directories(microhook PUBLIC include)
target_compile_features(microhook PUBLIC cxx_std_20)
if(MSVC)
    target_compile_options(microhook PRIVATE /W4 /permissive- /EHsc)
endif()

option(MICROHOOK_BUILD_EXAMPLES "Build examples" ON)
if(MICROHOOK_BUILD_EXAMPLES)
    add_executable(selfhook examples/selfhook/main.cpp)
    target_link_libraries(selfhook PRIVATE microhook)

    add_executable(apitest examples/apitest/main.cpp)
    target_link_libraries(apitest PRIVATE microhook)
endif()
