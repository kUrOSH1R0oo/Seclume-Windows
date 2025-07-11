# Seclume: Secure File Archiving Tool - Windows

Seclume is a robust, command-line file archiving tool designed for secure archiving, encryption, and compression of files and directories. It combines **AES-256-GCM** encryption, **zlib DEFLATE** and **LZMA** compression, and **HMAC-SHA256** integrity protection to ensure confidentiality, integrity, and efficient storage of sensitive data. Seclume is ideal for users who prioritize security and need a reliable way to archive, encrypt, and extract files.

This document provides a comprehensive guide to Seclume's features, installation, usage, encryption logic, and technical details for Windows.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Building from Source](#building-from-source)
- [Usage](#usage)
  - [Command-Line Options](#command-line-options)
  - [Modes](#modes)
    - [Archive Mode](#archive-mode)
    - [Extract Mode](#extract-mode)
    - [List Mode](#list-mode)
    - [View Comment](#view-comment)
  - [Examples](#examples)
- [Security Features](#security-features)
  - [Encryption](#encryption)
  - [Key Derivation](#key-derivation)
  - [Integrity Protection](#integrity-protection)
  - [Compression](#compression)
  - [Secure Randomization](#secure-randomization)
  - [File Permission Handling](#file-permission-handling)
- [Encryption Logic](#encryption-logic)
  - [Encryption Flow](#encryption-flow)
  - [ASCII Representation of Encryption Flow](#ascii-representation-of-encryption-flow)
- [Archive Format](#archive-format)
  - [Archive Header](#archive-header)
  - [File Entries](#file-entries)
- [Limitations](#limitations)
- [Error Handling](#error-handling)
- [Contributing](#contributing)
- [Reporting Bugs](#reporting-bugs)
- [License](#license)

## Features

Seclume provides the following key features:

- **Secure Encryption**: Uses **AES-256-GCM** for encrypting file data, metadata, and optional archive comments, ensuring confidentiality and authenticity.
- **Compression**: Employs **zlib DEFLATE** and **LZMA** with customizable compression levels (0-9) to reduce archive size.
- **Integrity Protection**: Computes **HMAC-SHA256** on the archive header to detect tampering.
- **Key Derivation**: Uses **PBKDF2** with SHA256 and 1,000,000 iterations for secure key derivation from passwords.
- **Recursive Directory Support**: Archives entire directory trees, with safeguards against path traversal attacks.
- **Archive Comments**: Allows adding encrypted comments to archives (up to 480 bytes after encryption overhead).
- **Dry Run Mode**: Simulates archiving operations without writing to disk, useful for testing.
- **Verbose Logging**: Supports multiple verbosity levels (`-vv` for debug, default for basic progress, or none for errors only).
- **Path Traversal Protection**: Prevents malicious filenames (e.g., containing `..`) from compromising security.
- **Password Strength Checking**: Enforces strong passwords unless **--weak-password** is specified.
- **Windows Path Support**: Handles Windows path conventions (e.g., backslashes) and supports paths up to 4096 bytes.

## Installation

The installation is pretty straightforward.

1. Clone or download the Seclume executable.
2. It comes in both 32-bit and 64-bit versions, each with a dedicated installer. Select the one that matches your system’s architecture.
   ```cmd
   installer.exe --install
   ```
   *Note: Be sure to run the installer with Administrator privileges.*
6. Verify the installation:
   ```cmd
   seclume -h
   ```

## Usage

Seclume operates in three primary modes: **archive**, **extract**, and **list**, with optional flags to modify behavior. The general syntax is:

```cmd
seclume [options] <mode> <archive.slm> <password> [files...]
```

Use backslashes (`\`) for file paths on Windows (e.g., `dir\file.txt`).

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-h`, `--help` | Displays the help message and exits. |
| `-vv` | Enables debug-level verbose output, showing detailed logging. |
| `-f` | Forces overwriting of existing files during archiving or extraction. |
| `-c`, `--comment <text>` | Adds a comment to the archive (archive mode only, max 480 bytes after encryption). |
| `-d`, `--dry-run` | Simulates archiving without writing to disk (archive mode only). |
| `-vc`, `--view-comment` | Displays the archive comment before executing the mode (not compatible with `-d` in archive mode). |
| `-ca`, `--compression-algo (zlib, lzma)` | Set compression algorithm (default = lzma). |
| `-cl`, `--compression-level <0-9>` | Set compression level (0 = no, 9 = max, default = 1). |
| `-wk`, `--weak-password` | Allows weak passwords in archive mode (NOT RECOMMENDED). |

### Modes

#### Archive Mode

Creates an encrypted `.slm` archive from specified files or directories.

```cmd
seclume [options] archive <archive.slm> <password> <file1> [file2 ...]
```

- **Inputs**: One or more files or directories (e.g., `file1.txt`, `C:\data\dir`).
- **Output**: A `.slm` archive file containing compressed and encrypted data.
- **Behavior**:
  - Recursively archives directories using Windows `FindFirstFile`/`FindNextFile`.
  - Normalizes paths to use backslashes (`\`) for Windows compatibility.
  - Compresses files using zlib or lzma at the specified compression level.
  - Encrypts file data, metadata, and comments using AES-256-GCM.
  - Generates a random salt and nonces for encryption.
  - Computes an HMAC-SHA256 for the archive header.
- **Options Supported**: `-f`, `-c`, `-d`, `-vv`, `-ca`, `-cl`, `-wk`.

#### Extract Mode

Extracts and decrypts files from a `.slm` archive to the current directory.

```cmd
seclume [options] extract <archive.slm> <password>
```

- **Inputs**: The `.slm` archive and the decryption password.
- **Output**: Extracted files with their original names.
- **Behavior**:
  - Verifies the archive header's HMAC.
  - Decrypts metadata and file data using AES-256-GCM.
  - Decompresses file data using zlib or lzma.
  - Creates parent directories as needed using Windows `_mkdir`.
- **Options Supported**: `-f`, `-vc`, `-vv`.

#### List Mode

Lists the contents of a `.slm` archive without extracting files.

```cmd
seclume [options] list <archive.slm> <password>
```

- **Inputs**: The `.slm` archive and the decryption password.
- **Output**: A table of file sizes and filenames (permissions not displayed on Windows).
- **Behavior**:
  - Verifies the archive header's HMAC.
  - Decrypts metadata to display filenames and sizes.
  - Skips file data, making it faster than extraction.
- **Options Supported**: `-vc`, `-vv`.

#### View Comment

Displays the encrypted comment in a `.slm` archive (if present).

```cmd
seclume -vc list <archive.slm> <password>
```

- **Behavior**:
  - Reads and verifies the archive header.
  - Decrypts the comment (if present) using AES-256-GCM.
  - Prints the comment or indicates if none exists.

### Examples

1. **Create an archive with default compression**:
   ```cmd
   seclume archive output.slm mypassWORD123! file1.txt C:\data\dir
   ```
   Archives `file1.txt` and the contents of `C:\data\dir` into `output.slm` with compression level 1.

2. **Create an archive with LZMA compression and maximum compression level**:
   ```cmd
   seclume --compression-algo lzma --compression-level 9 -c "My secure archive" archive output.slm mypassWORD123! C:\data\dir
   ```
   Uses maximum compression (level 9) and adds an encrypted comment.

3. **Perform a dry run to simulate archiving**:
   ```cmd
   seclume -d archive output.slm mypassWORD123! file1.txt
   ```
   Simulates archiving without creating the output file.

4. **Extract an archive with overwrite**:
   ```cmd
   seclume -f extract output.slm mypassWORD123!
   ```
   Extracts files, overwriting existing ones if necessary.

5. **List archive contents with verbose output**:
   ```cmd
   seclume -vv list output.slm mypassWORD123!
   ```
   Lists files with detailed debug logging.

6. **View archive comment before listing**:
   ```cmd
   seclume -vc list output.slm mypassWORD123!
   ```
   Displays the comment (if any) before listing the archive contents.

7. **Weak password handling**:
   ```cmd
   seclume -wk archive output.slm mypassword file1.txt
   ```
   Forces Seclume to use a weak password.

## Security Features

Seclume is designed with security as a top priority. Below are its core security mechanisms:

### Encryption

- **Algorithm**: AES-256-GCM (Galois/Counter Mode) for authenticated encryption.
- **Scope**: Encrypts file data, metadata (filenames, sizes), and archive comments.
- **Nonce**: Uses 12-byte random nonces generated with OpenSSL's cryptographically secure `RAND_bytes`.
- **Authentication**: Produces a 16-byte authentication tag for each encrypted block to ensure data integrity and authenticity.

### Key Derivation

- **Algorithm**: PBKDF2 with SHA256 and 1,000,000 iterations.
- **Salt**: 16-byte random salt stored in the archive header.
- **Keys**: Derives two 32-byte AES-256 keys:
  - One for file data encryption.
  - One for metadata and comment encryption.
- **Purpose**: Strengthens weak passwords and prevents brute-force attacks.

### Integrity Protection

- **Algorithm**: HMAC-SHA256.
- **Scope**: Computes a 32-byte HMAC over the archive header (excluding the HMAC field itself).
- **Purpose**: Detects tampering or corruption of the archive header.

### Compression

- **Algorithms**: zlib DEFLATE and LZMA.
- **Levels**: 0 (no compression) to 9 (maximum compression), default is 1.
- **Purpose**: Minimizes archive size while ensuring compatibility with both zlib and LZMA workflows. Note that compression may offer little to no size reduction for already compressed or incompressible data.

### Secure Randomization

- **Source**: OpenSSL's `RAND_bytes` for cryptographically secure random numbers.
- **Usage**: Generates salts and nonces for encryption and key derivation.
- **Purpose**: Ensures unpredictability in cryptographic operations.

### File Permission Handling

- **Storage**: Captures file metadata (filenames, sizes) during archiving.
- **Windows File Permission**: File permissions are stored in the archive.

## Encryption Logic

Seclume employs a robust encryption pipeline to ensure the confidentiality, integrity, and authenticity of archived data. The encryption process uses **AES-256-GCM**, **PBKDF2**, and **HMAC-SHA256**. Below is a detailed breakdown:

### Encryption Flow

1. **Password-Based Key Derivation**:
   - **Input**: User-provided password and a 16-byte random salt generated using `RAND_bytes`.
   - **Process**: PBKDF2 with SHA256 and 1,000,000 iterations derives two 32-byte AES-256 keys (file key and metadata key).
   - **Output**: Secure keys resistant to brute-force attacks.
   - **Purpose**: Strengthens password security.

2. **Header Creation and Protection**:
   - **Input**: Archive metadata (magic string "SLM", version, file count, compression algorithm, compression level, comment length, salt).
   - **Process**:
     - Populates header with metadata and random salt.
     - Computes HMAC-SHA256 over the header (excluding HMAC field) using the file key.
     - Encrypts comment (if provided) with AES-256-GCM using the metadata key, a 12-byte nonce, and a 16-byte tag.
   - **Output**: Tamper-proof header with encrypted comment.
   - **Purpose**: Protects metadata integrity and authenticity.

3. **File Compression**:
   - **Input**: Raw file data.
   - **Process**: Compresses each file using zlib or LZMA at the specified level (0-9).
   - **Output**: Compressed file data.
   - **Purpose**: Reduces archive size.

4. **File Data Encryption**:
   - **Input**: Compressed file data.
   - **Process**: Encrypts with AES-256-GCM using the file key, a 12-byte random nonce, and a 16-byte authentication tag.
   - **Output**: Encrypted file data with tag.
   - **Purpose**: Ensures confidentiality and integrity.

5. **Metadata Encryption**:
   - **Input**: File metadata (filename, compressed size, original size).
   - **Process**: Encrypts with AES-256-GCM using the metadata key, a 12-byte nonce, and a 16-byte tag.
   - **Output**: Encrypted `FileEntry` structure.
   - **Purpose**: Protects metadata from unauthorized access.

6. **Archive Assembly**:
   - **Process**: Writes header, encrypted metadata, file nonces, file tags, and encrypted file data to the `.slm` archive.
   - **Output**: Secure `.slm` archive.
   - **Purpose**: Combines components into a single file.

7. **Decryption and Extraction**:
   - **Process**:
     - Verifies header HMAC.
     - Decrypts comment (if present).
     - Decrypts metadata to retrieve filenames and sizes.
     - Decrypts and decompresses file data.
     - Writes files to disk, creating directories as needed.
   - **Purpose**: Ensures only authorized users can access contents.

### ASCII Representation of Encryption Flow

```
+-------------------+
| User Input        |
| - Password        |
| - Files/Dirs      |
| - Comment (opt)   |
| - Comp. Algo      |
| - Comp. Level     |
+-------------------+
          |
          v
+-------------------+
| Generate Salt     |
| (16 bytes, RAND)  |
+-------------------+
          |
          v
+-------------------+
| PBKDF2 (SHA256)   |
| - 1M iterations   |
| - Derive File Key |
| - Derive Meta Key |
+-------------------+
          |                 +------------------+
          v                 |                  |
+-------------------+       |                  v
| Create Header     |       |   +-----------------------------+
| - Magic, Version  |       |   | Compress File Data          |
| - File Count      |       |   | - zlib/lzma, Level: 0-9    |
| - Comp. Algo      |       |   +-----------------------------+
| - Comp. Level     |       |                  |
| - Salt            |       |                  v
| - Comment (enc)   |<------+                  v
| - HMAC (file key) |       |   +-----------------------------+
+-------------------+       |   | Encrypt File Data (AES-256) |
          |                 |   | - File Key, 12-byte Nonce  |
          v                 |   | - 16-byte Auth Tag         |
+-------------------+       |   +-----------------------------+
| For Each File:    |       |                  |
| - Read Data       |       |                  v
| - Stat (size)     |       |   +-----------------------------+
+-------------------+       |   | Encrypt Metadata (AES-256)  |
          |                 |   | - Meta Key, 12-byte Nonce  |
          v                 |   | - 16-byte Auth Tag         |
+-------------------+       |   | - Filename, Sizes          |
| Write to Archive  |<------+   +-----------------------------+
| - Header          |                          |
| - File Entries    |                          v
| - File Nonces     |       +-----------------------------+
| - File Tags       |       | Write to .slm Archive File  |
| - Encrypted Data  |       +-----------------------------+
+-------------------+
```

**Key Components**:
- **User Input**: Password, files, optional comment, compression algorithm, and level.
- **Salt Generation**: Random 16-byte salt for PBKDF2.
- **Key Derivation**: PBKDF2 produces two AES-256 keys.
- **Header**: Contains metadata and HMAC.
- **File Processing**: Compression, encryption of data and metadata.
- **Archive**: Combines all components into a `.slm` file.

## Archive Format

The `.slm` archive format is structured as follows:

### Archive Header

| Field | Size (Bytes) | Description |
|-------|--------------|-------------|
| `magic` | 3 | "SLM" identifier. |
| `version` | 1 | Archive format version (4 or 5). |
| `file_count` | 4 | Number of files in the archive. |
| `compression_algorithm` | 5 | Compression algorithm (zlib, lzma). |
| `compression_level` | 1 | Compression level (0-9). |
| `comment_len` | 4 | Length of encrypted comment. |
| `reserved` | 3 | Zeroed for future use. |
| `salt` | 16 | Random salt for PBKDF2. |
| `comment` | 512 | Encrypted comment, nonce, and tag. |
| `hmac` | 32 | HMAC-SHA256 of the header (excluding this field). |

### File Entries

Each file in the archive consists of:

1. **FileEntry Structure**:
   - `nonce` (12 bytes): Nonce for metadata encryption.
   - `tag` (16 bytes): Authentication tag for metadata.
   - `encrypted_data` (size of `FileEntryPlain`): Encrypted filename, sizes, and permissions.

2. **File Nonce** (12 bytes): Nonce for file data encryption.
3. **File Tag** (16 bytes): Authentication tag for file data.
4. **Encrypted File Data**: Compressed file data encrypted with AES-256-GCM.

The `FileEntryPlain` structure (decrypted metadata) contains:

| Field | Size (Bytes) | Description |
|-------|--------------|-------------|
| `filename` | 256 | Null-terminated filename. |
| `compressed_size` | 8 | Size of compressed and encrypted file data. |
| `original_size` | 8 | Original file size before compression. |
| `mode` | 4 | Windows file permissions. |
| `reserved` | 4 | Zeroed for future use. |

## Limitations

- **Maximum File Size**: 10GB per file (`MAX_FILE_SIZE`).
- **Maximum Files**: 1000 files per archive (`MAX_FILES`).
- **Maximum Path Length**: 4096 bytes, including filename components up to 255 bytes.
- **Maximum Comment Length**: 480 bytes (after encryption overhead).
- **No Incremental Updates**: Archives cannot be modified; they must be recreated.

## Error Handling

Seclume provides detailed error messages for:

- **Invalid Parameters**: Null pointers, empty files, or invalid compression levels.
- **File Access Errors**: Issues opening or reading files (Windows error codes included).
- **Cryptographic Failures**: Encryption, decryption, and key derivation errors.
- **Path Traversal**: Rejects filenames with `..` sequences.
- **Archive Corruption**: Detects invalid headers, versions, or HMAC mismatches.
- **Memory Allocation**: Reports failures to allocate buffers.
- **Path Length**: Rejects paths exceeding 4096 bytes or filename components exceeding 255 bytes.
- **Weak Passwords**: Enforces strong passwords unless `-wk` is specified.

Verbose mode (`-vv`) provides additional debug output, including file data snippets.

## Reporting Bugs

Report bugs to **lone_kuroshiro@protonmail.com**. Include:

- Seclume version (1.0.3).
- Steps to reproduce the issue.
- Relevant error messages or logs (use `-vv` for detailed output).

## License

Seclume is provided under BSD 3-Clause [License](https://github.com/kUrOSH1R0oo/Seclume/blob/main/LICENSE). Contact the maintainer for licensing details.
