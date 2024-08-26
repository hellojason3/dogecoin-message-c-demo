# Project Overview

This project is a simple C program that demonstrates the process of reading data from a file, processing it, and performing various cryptographic operations. The program reads data structures from a file, displays their contents, and performs operations like hashing, public key recovery, and Base58Check encoding.

## File Structure

- **data.txt**: The file containing the data to be processed by the program.
- **main.c**: The main C file where the core logic is implemented.

## Dependencies

Ensure you have the following libraries and dependencies installed to compile and run the program:

- Standard C library (`stdio.h`, `stdlib.h`)
- Cryptographic libraries for hashing and public key operations (not specified but assumed to be present)

## Compilation

To compile the program, use the following command:

```bash
gcc -o main main.c