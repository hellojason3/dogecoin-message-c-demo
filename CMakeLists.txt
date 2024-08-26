cmake_minimum_required(VERSION 3.24)
project(dogecoin_message_c C)

set(CMAKE_C_STANDARD 11)

add_executable(dogecoin_message_c main.c sha256.c sha256.h rmd160.h rmd160.c base58.c base58.h)

include_directories(/usr/local/include)
link_directories(/usr/local/lib)
link_libraries(/usr/local/lib/libsecp256k1.a)
