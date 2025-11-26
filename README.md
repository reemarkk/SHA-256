# SHA-256 Implementation in Pure C

This project contains a **manual implementation of the SHA-256 cryptographic hash function** in pure C.  
It does not use OpenSSL, Crypto++, or any external libraries. The implementation includes message padding, bitwise operations, message scheduling, and the 64-round compression algorithm.

---
## How SHA-256 Works

SHA-256 is a **cryptographic hash function** that takes an input of any size and produces a fixed 256-bit (32-byte) hash.  
It is widely used for data integrity verification, digital signatures, and password hashing.

### Step-by-Step Overview

1. **Initialize State**
   - SHA-256 starts with eight 32-bit constants (A–H) defined by the standard.
   - These form the initial internal state of the algorithm.

2. **Preprocessing / Padding**
   - The input message is padded so its length is a multiple of 512 bits (64 bytes).
   - Padding rules:
     - Append a single `1` bit.
     - Append `0` bits until the length is 64 bits short of a multiple of 512.
     - Append the original message length as a 64-bit big-endian integer.
   - This ensures the total message length is a multiple of 512 bits.

3. **Message Scheduling**
   - Each 512-bit block is divided into 16 words (32-bit each).
   - These 16 words are expanded into a **64-word schedule** using the SIGMA functions.

4. **Compression Function (64 Rounds)**
   - For each block:
     - Copy the current state into temporary variables (`a`–`h`).
     - For 64 rounds:
       - Compute temporary values `t1` and `t2` using:
         - Choice function `CH`
         - Majority function `MAJ`
         - Bitwise rotations `ROTRIGHT`
         - Round constants `K[i]`
         - The message schedule `m[i]`
       - Update the working variables `a`–`h`.
     - Add the results back into the internal state.

5. **Finalization**
   - After processing all blocks, the internal state contains the final hash.
   - The state is converted into a 32-byte array (SHA256_HASH) as the output.

### Key Functions in the C Implementation

| Function                  | Purpose |
|----------------------------|---------|
| `ROTRIGHT(x, n)`           | Circular right rotation of 32-bit word `x` by `n` bits. |
| `CH(x, y, z)`              | Choice function: selects bits from `y` or `z` based on `x`. |
| `MAJ(x, y, z)`             | Majority function: picks the majority bit among `x`, `y`, and `z`. |
| `EP0(x), EP1(x)`           | Big sigma functions used in compression rounds. |
| `SIGMA0(x), SIGMA1(x)`     | Small sigma functions used in message schedule expansion. |
| `sha256_transform()`       | Performs 64 rounds of compression on a 512-bit block. |
| `sha256_update()`          | Feeds input data into SHA-256 and processes blocks as they fill. |
| `sha256_final()`           | Adds padding, appends length, finalizes the hash output. |
| `SHA_256()`                | Convenient wrapper to hash any buffer in one call. |


## Prerequisites

Before building and running this SHA-256 implementation, ensure you have the following:

### 1. Compiler
- **C compiler** that supports C11 standard:
  - macOS: `clang` (usually pre-installed)
  - Linux: `gcc` or `clang`

### 2. Build Tools
- Basic command-line tools:
  - Terminal or command prompt access

### 3. Optional (for VS Code users)
- **Visual Studio Code**
- C/C++ extension installed
- Optional: `.vscode/tasks.json` configured for easy build

### 4. Operating System
- macOS, Linux, or Windows
- No special libraries required — the project uses **only standard C library**.

---
## Purpose

The purpose of this project is to provide a **manual implementation of the SHA-256 cryptographic hash function** in pure C, without relying on external libraries.  

It serves several goals:

1. **Educational:** Understand how SHA-256 works at a low level, including message padding, scheduling, and the 64-round compression function.  
2. **Practical:** Offer a simple, portable SHA-256 implementation for hashing text, integers, or binary data.  
3. **Reference:** Provide a working example of a cryptographic hash in C that can be integrated into other projects or used for learning purposes.  

This implementation demonstrates both the **security properties** of SHA-256 and the **core algorithm structure** in an understandable, self-contained way.




