#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a) {
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main () {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *m1 = BN_new();
    BIGNUM *m2 = BN_new();
    BIGNUM *s1 = BN_new();
    BIGNUM *s2 = BN_new();

    // 1. กำหนดค่า Key (n, d) เดิมจาก Task 2
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E47941148AACBC26AA381CD7D30D");

    // 2. กำหนดค่า Message M1 และ M2 (ในรูปแบบ Hex)
    BN_hex2bn(&m1, "49206f776520796f752024323030302e"); // $2000.
    BN_hex2bn(&m2, "49206f776520796f752024333030302e"); // $3000.

    // 3. สร้าง Signature: S = M^d mod n
    BN_mod_exp(s1, m1, d, n, ctx);
    BN_mod_exp(s2, m2, d, n, ctx);

    // 4. แสดงผลเพื่อเปรียบเทียบ
    printf("--- Task 4: Digital Signature ---\n");
    printBN("Signature S1 ($2000): ", s1);
    printBN("Signature S2 ($3000): ", s2);

    BN_free(n); BN_free(d); BN_free(m1); BN_free(m2);
    BN_free(s1); BN_free(s2);
    BN_CTX_free(ctx);
    return 0;
}