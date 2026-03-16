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
    BIGNUM *n = BN_new(); // Allocate memory for public modulus 'n'
    BIGNUM *e = BN_new(); // Allocate memory for public exponent 'e' (Used for verification)
    BIGNUM *s = BN_new(); // Allocate memory for the digital signature 's'
    BIGNUM *m_res = BN_new(); // Allocate memory for the recovered message during verification

    // Assign Alice's public modulus 'n'
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    // Assign Alice's public exponent 'e'
    BN_hex2bn(&e, "010001");
    
    // --- Case 1: Original valid signature (ending with 2F) ---
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    // Verification: M' = (S ^ e) mod n
    BN_mod_exp(m_res, s, e, n, ctx); 
    printf("--- Case 1: Original Signature ---\n"); // Print header
    printBN("Resulting M' (Hex): ", m_res); // Print recovered message M'

    // --- Case 2: Corrupted signature (ending byte changed from 2F to 3F) ---
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
    // Verification with corrupted signature: M'' = (S_corrupted ^ e) mod n
    BN_mod_exp(m_res, s, e, n, ctx);
    printf("\n--- Case 2: Corrupted Signature (2F -> 3F) ---\n"); // Print header
    printBN("Resulting M'' (Hex): ", m_res); // Print incorrectly recovered message

    // Memory cleanup
    BN_free(n); BN_free(e); BN_free(s); BN_free(m_res);
    BN_CTX_free(ctx);
    
    return 0; // Return 0 to indicate successful execution
}