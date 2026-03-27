#include <stdio.h>
#include <openssl/bn.h>

// Helper function to print a BIGNUM variable in hexadecimal format
void printBN(char *msg, BIGNUM * a) {
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str); // Free the memory allocated by BN_bn2hex
}

int main () {
    // Initialize the BIGNUM context, which is required for temporary variables in BN operations
    BN_CTX *ctx = BN_CTX_new();

    // Allocate memory for BIGNUM variables
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *d = BN_new();
    
    // Auxiliary variables for calculating (p-1) and (q-1)
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();
    BIGNUM *one = BN_new();
    BN_dec2bn(&one, "1"); // Set the value of 'one' to 1 (Decimal)

    // 1. Assign given values for p, q, and e (Hexadecimal representation)
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    // 2. Compute Euler's totient function: phi(n) = (p-1) * (q-1)
    BN_sub(p_minus_1, p, one); // p_minus_1 = p - 1
    BN_sub(q_minus_1, q, one); // q_minus_1 = q - 1
    BN_mul(phi, p_minus_1, q_minus_1, ctx); // phi = (p-1) * (q-1)

    // 3. Compute the private key: d = e^-1 mod phi(n)
    // The BN_mod_inverse function calculates the modular multiplicative inverse
    if (BN_mod_inverse(d, e, phi, ctx)) {
        printf("Successfully derived the private key!\n");
        printBN("Private Key (d) = ", d);
    } else {
        // Fallback in case e and phi(n) are not coprime
        printf("Error: Modular inverse does not exist.\n");
    }

    // 4. Memory Cleanup: Free all allocated BIGNUM variables and context
    BN_free(p); BN_free(q); BN_free(e); BN_free(n);
    BN_free(phi); BN_free(d); BN_free(p_minus_1);
    BN_free(q_minus_1); BN_free(one);
    BN_CTX_free(ctx);

    return 0;
}