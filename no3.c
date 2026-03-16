#include <stdio.h>
#include <openssl/bn.h>

// ฟังก์ชันสำหรับพิมพ์ค่า BIGNUM ในรูปแบบเลขฐาน 16
void printBN(char *msg, BIGNUM * a) {
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main () {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *m = BN_new(); // ตัวแปรสำหรับเก็บผลลัพธ์ข้อความที่ถอดรหัสแล้ว (Plaintext)

    // 1. กำหนดค่า Key จาก Task 2
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E47941148AACBC26AA381CD7D30D");

    // 2. กำหนดค่า Ciphertext (C) จากโจทย์ Task 3
    BN_hex2bn(&c, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

    // 3. ทำการถอดรหัส: M = C^d mod n
    BN_mod_exp(m, c, d, n, ctx);

    // 4. แสดงผลลัพธ์ในรูปแบบ Hex
    printf("--- RSA Decryption Task 3 ---\n");
    printBN("Decrypted Message (M) in Hex: ", m);

    // ล้างหน่วยความจำ
    BN_free(n); BN_free(d); BN_free(c); BN_free(m);
    BN_CTX_free(ctx);

    return 0;
}