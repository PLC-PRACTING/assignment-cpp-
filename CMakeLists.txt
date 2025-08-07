cmake_minimum_required(VERSION 3.16)
project(ToyC_Compiler)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# Include directories
include_directories(src)

# Source files
set(SOURCES
    src/token.cpp
    src/lexer.cpp
    src/parser.cpp
    src/semantic.cpp
    src/codegen.cpp
    src/main.cpp
)

# Create executable
add_executable(toyc_compiler ${SOURCES})

# 根据编译器类型，添加相应的编译警告选项
if (MSVC)
    # 如果是微软的 Visual C++ 编译器，使用 /W4 警告等级
    target_compile_options(toyc_compiler PRIVATE /W4)
else()
    # 如果是 GCC/Clang 或其他编译器，使用 -Wall 和 -Wextra
    target_compile_options(toyc_compiler PRIVATE -Wall -Wextra)
endif()

# Custom target for testing
add_custom_target(test-basic
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/toyc_compiler
    DEPENDS toyc_compiler
    COMMENT "Running basic tests"
)

# Custom target for testing with provided cases
add_custom_target(test-cases
    COMMAND echo "Testing with provided test cases..."
    DEPENDS toyc_compiler
    COMMENT "Running test cases"
)