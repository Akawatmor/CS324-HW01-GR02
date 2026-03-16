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
    BIGNUM *e = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *m_res = BN_new();

    // 1. กำหนดค่า Public Key และ Signature จากโจทย์
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&e, "010001");
    
    // --- กรณีที่ 1: ลายเซ็นปกติ (ลงท้ายด้วย 2F) ---
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_mod_exp(m_res, s, e, n, ctx); // M' = S^e mod n
    printf("--- Case 1: Original Signature ---\n");
    printBN("Resulting M' (Hex): ", m_res);

    // --- กรณีที่ 2: ลายเซ็นถูกแก้ไข (เปลี่ยน 2F เป็น 3F) ---
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
    BN_mod_exp(m_res, s, e, n, ctx);
    printf("\n--- Case 2: Corrupted Signature (2F -> 3F) ---\n");
    printBN("Resulting M'' (Hex): ", m_res);

    BN_free(n); BN_free(e); BN_free(s); BN_free(m_res);
    BN_CTX_free(ctx);
    return 0;
}