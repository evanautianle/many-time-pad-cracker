# many-time-pad-cracker

Analyze Ciphertexts: The script reads ciphertexts from a file and splits them into columns (bytes at the same position across all ciphertexts). It uses XOR to compare pairs of bytes in each column to identify likely spaces in the plaintext.

Guess the Key: For each column, the script determines the most probable key byte by assuming spaces in the plaintext and calculating the XOR with the space character (ASCII 0x20).

Decrypt and Output: Using the guessed key, the script decrypts the ciphertexts by XORing each byte with the corresponding key byte and outputs the plaintexts, replacing unprintable characters with ?.
