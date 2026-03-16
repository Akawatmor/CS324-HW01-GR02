#include <stdio.h>
#include <openssl/bn.h>

// Function to print a BIGNUM variable in a readable hexadecimal format
void printBN(char *msg, BIGNUM * a) {
    char * number_str = BN_bn2hex(a); // Convert BIGNUM 'a' to a hexadecimal string
    printf("%s %s\n", msg, number_str); // Print the custom message along with the hex string
    OPENSSL_free(number_str); // Free the memory allocated by BN_bn2hex
}

int main () {
    BN_CTX *ctx = BN_CTX_new(); // Allocate a new context for BIGNUM temporary operations
    BIGNUM *n = BN_new(); // Allocate memory for modulus 'n'
    BIGNUM *d = BN_new(); // Allocate memory for private exponent 'd'
    BIGNUM *c = BN_new(); // Allocate memory for the ciphertext 'c'
    BIGNUM *m = BN_new(); // Allocate memory for the resulting decrypted plaintext 'm'

    // Assign the modulus 'n' from Task 2
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    // Assign the private key 'd' provided in the lab instructions
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    // Assign the ciphertext 'C' that needs to be decrypted
    BN_hex2bn(&c, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

    // Perform modular exponentiation for decryption: m = (c ^ d) mod n
    BN_mod_exp(m, c, d, n, ctx);

    // Output the decrypted result in hex format
    printf("--- RSA Decryption Task 3 ---\n"); // Print header
    printBN("Decrypted Message (M) in Hex: ", m); // Print the recovered plaintext in hex

    // Memory cleanup: free all allocated BIGNUM variables and context
    BN_free(n); BN_free(d); BN_free(c); BN_free(m);
    BN_CTX_free(ctx);

    return 0; // Return 0 to indicate successful execution
}