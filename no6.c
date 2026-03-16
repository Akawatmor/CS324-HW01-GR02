#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a) {
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main () {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n_ca = BN_new(); // Modulus ของ CA
    BIGNUM *e_ca = BN_new(); // Exponent ของ CA
    BIGNUM *s = BN_new();    // Signature จาก Server Cert
    BIGNUM *res = BN_new();  // ผลลัพธ์จากการถอดลายเซ็น

    // --- กรอกข้อมูลที่คุณสกัดมาได้จากขั้นตอนที่ 2 ---
    // (ตัวอย่างค่าด้านล่างเป็นแค่ Placeholder กรุณาเปลี่ยนเป็นค่าจริงที่คุณหาได้)
    BN_hex2bn(&n_ca, "8F347587AF8472148D0710916F03ACF1D408359A19F29B1889346C988F7AD4DDEA05E8DE1B7C8C5412BA798AFB180D0D7C9CF3BD38E4A85EC633CB46896F46A0E937638DDCCCD5974E32AD7B1D2305B9F57B494398D0BC57C7537818B1EDA754B27C86BEF05445BC87BA99591DF4B8DB00FB814F462B625EB13AA52A1723ACA2BEC58EE55EFD711E7DA4B4237D0452B234D2DF99AC87C64C595FF8E64F8E7592C2B2304692D0B60DC7E48967FF3F54942765E301C84A2C842F655FCDAD5CFDA6AD415BDC4C3F1796917DA9D83C532A1CD0E6D477E6434AC2B7F848A2CDAD63B5256B96721D81456F8669C4E4E6784C31E6A17FA701730A87EF878972CCD3C58D");
    BN_hex2bn(&e_ca, "010001"); // ปกติจะเป็นค่านี้
    BN_hex2bn(&s, "7eaaf7a67112d476f6dbecb83c7d01bc200627ac05e74d0582e3afc5335e48a861ca3da6ebafd2fa61193d7164fc4a472dd68b0fe915485ef1a2f5d03cc7f14a3db3bfd82e64f66b1b9ad2905fbb877300a6fad07cf3e5d4194b769ce9cbd75831b056420b89686232ec68230cc963b2725bcca84262e3b7a839bc3fdfd7bd2ec0c5aaab24c064fe3921b334fce8d864288681e67714cc6427220e0a99a77a865313b3e666aeeb3ab6e261baf5b0ac51adfed2902ac9e244071da07b8047100fe1fca1910db34ece279fa7d141c3fd8ccc4df1b578291226bd193efb553f6083992f17cc4c96f60717ea49265c5181576743fa9dd39a9d80cb0967dc9929e1cf");

    // คำนวณ: res = S^e mod n
    BN_mod_exp(res, s, e_ca, n_ca, ctx);

    printf("--- Task 6: Manual X.509 Verification ---\n");
    printBN("Decrypted Signature (Expected Hash inside): ", res);

    BN_free(n_ca); BN_free(e_ca); BN_free(s); BN_free(res);
    BN_CTX_free(ctx);
    return 0;
}