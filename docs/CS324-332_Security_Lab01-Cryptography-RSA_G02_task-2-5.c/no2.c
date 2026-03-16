#include <stdio.h>
#include <openssl/bn.h>

// Function to print a BIGNUM variable in a readable hexadecimal format
void printBN(char *msg, BIGNUM * a) {
    char * number_str = BN_bn2hex(a); // Convert BIGNUM 'a' to a hexadecimal string
    printf("%s %s\n", msg, number_str); // Print the custom message along with the hex string
    OPENSSL_free(number_str); // Free the memory allocated by BN_bn2hex to prevent memory leaks
}

int main () {
    BN_CTX *ctx = BN_CTX_new(); // Allocate a new context for BIGNUM temporary variables
    BIGNUM *n = BN_new(); // Allocate memory for public key modulus 'n'
    BIGNUM *e = BN_new(); // Allocate memory for public exponent 'e'
    BIGNUM *m = BN_new(); // Allocate memory for the plaintext message 'm'
    BIGNUM *c = BN_new(); // Allocate memory for the resulting ciphertext 'c'

    // Assign the public modulus 'n' from the given hexadecimal string
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    // Assign the public exponent 'e' from the given hexadecimal string
    BN_hex2bn(&e, "010001");

    // Assign the hex representation of "A top secret!" to the message variable 'm'
    BN_hex2bn(&m, "4120746f702073656372657421");

    // Perform modular exponentiation: c = (m ^ e) mod n
    BN_mod_exp(c, m, e, n, ctx);

    // Output the results
    printf("--- RSA Encryption Task 2 ---\n"); // Print header
    printBN("Original Message (M) in Hex: ", m); // Print the original message in hex
    printBN("Ciphertext (C): ", c); // Print the resulting encrypted ciphertext

    // Memory cleanup: free all allocated BIGNUM variables and context
    BN_free(n); BN_free(e); BN_free(m); BN_free(c);
    BN_CTX_free(ctx);

    return 0; // Return 0 to indicate successful execution
}