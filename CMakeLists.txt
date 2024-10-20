cmake_minimum_required(VERSION 3.10)


project(File_Encryptor)
set(CMAKE_C_STANDARD 11)

include_directories(include)
set(SOURCES
main.c
)

add_executable(file_encrypt ${SOURCES})

find_pachage(OpenSSL REQUIRED)
target_link_libraries(file_encrypt OpenSSL::Crypto)
