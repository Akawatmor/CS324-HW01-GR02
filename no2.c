#include <stdio.h>
#include <openssl/bn.h>

// ฟังก์ชันสำหรับพิมพ์ค่า BIGNUM ในรูปแบบเลขฐาน 16
void printBN(char *msg, BIGNUM * a) {
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main () {
    // จองหน่วยความจำสำหรับ Context และตัวแปร BIGNUM
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *c = BN_new(); // ตัวแปรสำหรับเก็บผลลัพธ์ Ciphertext

    // 1. กำหนดค่า Public Key (n, e) จากโจทย์
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");

    // 2. กำหนดค่า Message (M) 
    // แปลงจาก "A top secret!" เป็น Hex: 4120746f702073656372657421
    BN_hex2bn(&m, "4120746f702073656372657421");

    // 3. ทำการเข้ารหัส: C = M^e mod n
    // ใช้ฟังก์ชัน BN_mod_exp (Modular Exponentiation)
    BN_mod_exp(c, m, e, n, ctx);

    // 4. แสดงผลลัพธ์
    printf("--- RSA Encryption Task 2 ---\n");
    printBN("Original Message (M) in Hex: ", m);
    printBN("Ciphertext (C): ", c);

    // ล้างหน่วยความจำหลังใช้งานเสร็จ
    BN_free(n); BN_free(e); BN_free(m); BN_free(c);
    BN_CTX_free(ctx);

    return 0;
}