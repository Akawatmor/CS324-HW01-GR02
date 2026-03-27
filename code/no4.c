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
    BIGNUM *d = BN_new(); // Allocate memory for private exponent 'd' (Used for signing)
    BIGNUM *m1 = BN_new(); // Allocate memory for the first message ($2000)
    BIGNUM *m2 = BN_new(); // Allocate memory for the second message ($3000)
    BIGNUM *s1 = BN_new(); // Allocate memory for the first signature
    BIGNUM *s2 = BN_new(); // Allocate memory for the second signature

    // Assign the modulus 'n' and private key 'd' (The signer's key)
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    // Assign the hex representation of "I owe you $2000."
    BN_hex2bn(&m1, "49206f776520796f752024323030302e"); 
    // Assign the hex representation of "I owe you $3000." (Only one byte changed)
    BN_hex2bn(&m2, "49206f776520796f752024333030302e"); 

    // Generate Signature 1: s1 = (m1 ^ d) mod n
    BN_mod_exp(s1, m1, d, n, ctx);
    // Generate Signature 2: s2 = (m2 ^ d) mod n
    BN_mod_exp(s2, m2, d, n, ctx);

    // Output both signatures to observe the differences
    printf("--- Task 4: Digital Signature ---\n"); // Print header
    printBN("Signature S1 ($2000): ", s1); // Print the signature for the original message
    printBN("Signature S2 ($3000): ", s2); // Print the signature for the modified message

    // Memory cleanup
    BN_free(n); BN_free(d); BN_free(m1); BN_free(m2);
    BN_free(s1); BN_free(s2);
    BN_CTX_free(ctx);
    
    return 0; // Return 0 to indicate successful execution
}