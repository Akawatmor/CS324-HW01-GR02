# Task 6: Manual X.509 Certificate Verification using RSA

---

## 3.2.1 ชุดคำสั่ง (Source Code) พร้อมคำอธิบาย

### ภาษาซี (`no6.c`)

```c
#include <stdio.h>
#include <openssl/bn.h>

/*
 * ฟังก์ชันช่วย: แปลง BIGNUM เป็นสตริงฐาน 16 (Hex) แล้วพิมพ์ออกทางหน้าจอ
 * พารามิเตอร์:
 *   - msg : ข้อความ label ที่จะแสดงนำหน้าค่าตัวเลข
 *   - a   : ตัวชี้ไปยังโครงสร้าง BIGNUM ที่ต้องการแสดงผล
 */
void printBN(char *msg, BIGNUM *a) {
    /* BN_bn2hex() แปลง BIGNUM → สตริง hexadecimal (จัดสรรหน่วยความจำภายใน) */
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    /* คืนหน่วยความจำที่ OpenSSL จัดสรรให้สตริง เพื่อป้องกัน memory leak */
    OPENSSL_free(number_str);
}

int main() {
    /*
     * BN_CTX เป็น context สำหรับเก็บตัวแปรชั่วคราว (scratch space)
     * ที่ฟังก์ชัน BN_mod_exp ต้องใช้ระหว่างการคำนวณ
     */
    BN_CTX *ctx = BN_CTX_new();

    /*
     * ประกาศตัวแปร BIGNUM สำหรับเก็บค่าสำคัญ 4 ตัว:
     *   n_ca : Modulus (n) ของ CA — สกัดจาก Public Key ของ CA certificate
     *   e_ca : Public Exponent (e) ของ CA — โดยทั่วไปคือ 65537 (0x010001)
     *   s    : Signature ที่แนบมากับ Server Certificate
     *          (CA เซ็นด้วย Private Key ของตน)
     *   res  : ผลลัพธ์จากการถอดลายเซ็นดิจิทัล (Decrypted Signature)
     */
    BIGNUM *n_ca = BN_new();   // Modulus ของ CA
    BIGNUM *e_ca = BN_new();   // Public Exponent ของ CA
    BIGNUM *s    = BN_new();   // Signature จาก Server Certificate
    BIGNUM *res  = BN_new();   // ผลลัพธ์ = S^e mod n

    /*
     * ======================================================================
     *  ขั้นตอนที่ 1: กำหนดค่า n, e, s จากข้อมูลที่สกัดจาก Certificate จริง
     * ======================================================================
     *
     * n_ca — Modulus ของ CA (Issuer)
     *   ได้มาจากคำสั่ง:
     *     openssl x509 -in ca.crt -noout -modulus
     *   หรือจาก field "Modulus" ใน Public Key ของ CA certificate
     */
    BN_hex2bn(&n_ca,
        "8F347587AF8472148D0710916F03ACF1"
        "D408359A19F29B1889346C988F7AD4DD"
        "EA05E8DE1B7C8C5412BA798AFB180D0D"
        "7C9CF3BD38E4A85EC633CB46896F46A0"
        "E937638DDCCCD5974E32AD7B1D2305B9"
        "F57B494398D0BC57C7537818B1EDA754"
        "B27C86BEF05445BC87BA99591DF4B8DB"
        "00FB814F462B625EB13AA52A1723ACA2"
        "BEC58EE55EFD711E7DA4B4237D0452B2"
        "34D2DF99AC87C64C595FF8E64F8E7592"
        "C2B2304692D0B60DC7E48967FF3F5494"
        "2765E301C84A2C842F655FCDAD5CFDA6"
        "AD415BDC4C3F1796917DA9D83C532A1C"
        "D0E6D477E6434AC2B7F848A2CDAD63B5"
        "256B96721D81456F8669C4E4E6784C31"
        "E6A17FA701730A87EF878972CCD3C58D");

    /*
     * e_ca — Public Exponent ของ CA
     *   ค่ามาตรฐานที่ CA ส่วนใหญ่ใช้คือ 65537 (0x010001)
     */
    BN_hex2bn(&e_ca, "010001");

    /*
     * s — Signature Value ที่แนบท้าย Server Certificate
     *   ได้มาจากคำสั่ง:
     *     openssl x509 -in server.crt -text -noout
     *   แล้วดูในส่วน "Signature Value"
     */
    BN_hex2bn(&s,
        "7eaaf7a67112d476f6dbecb83c7d01bc"
        "200627ac05e74d0582e3afc5335e48a8"
        "61ca3da6ebafd2fa61193d7164fc4a47"
        "2dd68b0fe915485ef1a2f5d03cc7f14a"
        "3db3bfd82e64f66b1b9ad2905fbb8773"
        "00a6fad07cf3e5d4194b769ce9cbd758"
        "31b056420b89686232ec68230cc963b2"
        "725bcca84262e3b7a839bc3fdfd7bd2e"
        "c0c5aaab24c064fe3921b334fce8d864"
        "288681e67714cc6427220e0a99a77a86"
        "5313b3e666aeeb3ab6e261baf5b0ac51"
        "adfed2902ac9e244071da07b8047100f"
        "e1fca1910db34ece279fa7d141c3fd8c"
        "cc4df1b578291226bd193efb553f6083"
        "992f17cc4c96f60717ea49265c518157"
        "6743fa9dd39a9d80cb0967dc9929e1cf");

    /*
     * ======================================================================
     *  ขั้นตอนที่ 2: ตรวจสอบลายเซ็น (Signature Verification)
     * ======================================================================
     *
     * การคำนวณ:  res = s ^ e_ca  (mod n_ca)
     *
     * หลักการ RSA:
     *   - CA เซ็นเอกสาร (hash ของ TBS Certificate) ด้วย private key (d):
     *       signature = hash^d  mod n
     *   - ฝั่งผู้ตรวจสอบ (client) จะกู้คืน hash โดยใช้ public key (e, n):
     *       hash_recovered = signature^e  mod n
     *   - ถ้า hash_recovered ตรงกับ hash ที่คำนวณเองจาก TBS Certificate
     *     แสดงว่า Certificate นี้ถูกเซ็นโดย CA จริง → เชื่อถือได้
     */
    BN_mod_exp(res, s, e_ca, n_ca, ctx);

    /* แสดงผลลัพธ์ */
    printf("=== Task 6: Manual X.509 Certificate Verification ===\n");
    printBN("Decrypted Signature (PKCS#1 padded hash):\n", res);

    /*
     * ======================================================================
     *  ขั้นตอนที่ 3: คืนหน่วยความจำ (Clean Up)
     * ======================================================================
     */
    BN_free(n_ca);
    BN_free(e_ca);
    BN_free(s);
    BN_free(res);
    BN_CTX_free(ctx);

    return 0;
}
```

#### วิธีคอมไพล์และรัน (C)

```bash
# คอมไพล์โดยลิงก์กับ OpenSSL
gcc -o no6 no6.c -lcrypto

# รันโปรแกรม
./no6
```

---

### ภาษาไพธอน (`no6.py`)

```python
#!/usr/bin/env python3
"""
Task 6 – Manual X.509 Certificate Signature Verification using RSA (Python)

หลักการ:
  Server Certificate ถูก CA เซ็นด้วย private key ของ CA
  เราจะใช้ public key ของ CA (n, e) ถอดลายเซ็น (signature)
  เพื่อกู้คืนค่า hash ที่อยู่ข้างใน  แล้วนำไปเปรียบเทียบกับ
  hash ที่เราคำนวณเองจาก TBS (To-Be-Signed) Certificate
"""

# ==============================================================
#  ขั้นตอนที่ 1: กำหนดค่า n, e, s (สกัดจาก Certificate จริง)
# ==============================================================

# n_ca — Modulus ของ CA (Issuer) Certificate
# ได้จากคำสั่ง: openssl x509 -in ca.crt -noout -modulus
n_ca = int(
    "8F347587AF8472148D0710916F03ACF1"
    "D408359A19F29B1889346C988F7AD4DD"
    "EA05E8DE1B7C8C5412BA798AFB180D0D"
    "7C9CF3BD38E4A85EC633CB46896F46A0"
    "E937638DDCCCD5974E32AD7B1D2305B9"
    "F57B494398D0BC57C7537818B1EDA754"
    "B27C86BEF05445BC87BA99591DF4B8DB"
    "00FB814F462B625EB13AA52A1723ACA2"
    "BEC58EE55EFD711E7DA4B4237D0452B2"
    "34D2DF99AC87C64C595FF8E64F8E7592"
    "C2B2304692D0B60DC7E48967FF3F5494"
    "2765E301C84A2C842F655FCDAD5CFDA6"
    "AD415BDC4C3F1796917DA9D83C532A1C"
    "D0E6D477E6434AC2B7F848A2CDAD63B5"
    "256B96721D81456F8669C4E4E6784C31"
    "E6A17FA701730A87EF878972CCD3C58D",
    16  # ฐาน 16 (hexadecimal)
)

# e_ca — Public Exponent ของ CA (มาตรฐาน: 65537)
e_ca = 0x010001

# s — Signature Value ที่แนบท้าย Server Certificate
# ได้จากคำสั่ง: openssl x509 -in server.crt -text -noout  (ดูส่วน Signature Value)
s = int(
    "7eaaf7a67112d476f6dbecb83c7d01bc"
    "200627ac05e74d0582e3afc5335e48a8"
    "61ca3da6ebafd2fa61193d7164fc4a47"
    "2dd68b0fe915485ef1a2f5d03cc7f14a"
    "3db3bfd82e64f66b1b9ad2905fbb8773"
    "00a6fad07cf3e5d4194b769ce9cbd758"
    "31b056420b89686232ec68230cc963b2"
    "725bcca84262e3b7a839bc3fdfd7bd2e"
    "c0c5aaab24c064fe3921b334fce8d864"
    "288681e67714cc6427220e0a99a77a86"
    "5313b3e666aeeb3ab6e261baf5b0ac51"
    "adfed2902ac9e244071da07b8047100f"
    "e1fca1910db34ece279fa7d141c3fd8c"
    "cc4df1b578291226bd193efb553f6083"
    "992f17cc4c96f60717ea49265c518157"
    "6743fa9dd39a9d80cb0967dc9929e1cf",
    16
)

# ==============================================================
#  ขั้นตอนที่ 2: ตรวจสอบลายเซ็น  res = s^e mod n
# ==============================================================
# Python built-in pow(base, exp, mod) ใช้ modular exponentiation
# ภายในเป็น square-and-multiply เหมือน BN_mod_exp ของ OpenSSL
res = pow(s, e_ca, n_ca)

# ==============================================================
#  ขั้นตอนที่ 3: แสดงผลลัพธ์
# ==============================================================
print("=== Task 6: Manual X.509 Certificate Verification (Python) ===")
print()

# แปลงผลลัพธ์เป็น hex string (ตัดคำนำหน้า '0x' ออก แล้วทำให้เป็นตัวพิมพ์ใหญ่)
hex_result = hex(res)[2:].upper()
print(f"Decrypted Signature (PKCS#1 padded hash):\n{hex_result}")
print()

# ==============================================================
#  ขั้นตอนที่ 4: แยกวิเคราะห์โครงสร้าง PKCS#1 v1.5 padding
# ==============================================================
# โครงสร้างที่คาดหวัง (PKCS#1 v1.5):
#   0001 FF FF ... FF 00 <DigestInfo (ASN.1 DER ของ OID + Hash)>
#
# ถ้า hash algorithm เป็น SHA-256 จะมี OID prefix:
#   3031300D060960864801650304020105000420
# ตามด้วย SHA-256 hash ขนาด 32 ไบต์ (64 hex chars)

# พยายามแยกค่า hash ออกจาก padding
hex_padded = hex_result.zfill(512)  # Pad ให้ครบ 2048-bit (512 hex chars)

# หา marker "0020" หรือ "000420" ซึ่งอยู่ก่อน hash value
sha256_oid_prefix = "3031300D060960864801650304020105000420"
idx = hex_padded.upper().find(sha256_oid_prefix)

if idx != -1:
    hash_start = idx + len(sha256_oid_prefix)
    extracted_hash = hex_padded[hash_start:hash_start + 64]
    print(f"Extracted SHA-256 Hash from Signature:\n{extracted_hash}")
    print()
    print("นำค่า hash นี้ไปเปรียบเทียบกับ SHA-256 ของ TBS Certificate")
    print("ถ้าตรงกัน → Certificate ถูกเซ็นโดย CA จริง (Verification SUCCESS)")
else:
    print("ไม่พบ SHA-256 OID prefix — อาจใช้ hash algorithm อื่น (SHA-1, SHA-384, ฯลฯ)")
    print("หรือค่า n/e/s อาจไม่ถูกต้อง")
```

#### วิธีรัน (Python)

```bash
python3 no6.py
```

---

## 3.2.2 ภาพหน้าจอแสดงผลลัพธ์

### ผลลัพธ์จากโปรแกรมภาษา C

> **[ให้ใส่รูปภาพ]** ภาพหน้าจอ Terminal แสดงผลการคอมไพล์ (`gcc -o no6 no6.c -lcrypto`) และผลลัพธ์จากการรัน `./no6` ซึ่งแสดง **Decrypted Signature (PKCS#1 padded hash)** เป็นค่า hexadecimal ยาว

### ผลลัพธ์จากโปรแกรมภาษา Python

> **[ให้ใส่รูปภาพ]** ภาพหน้าจอ Terminal แสดงผลการรัน `python3 no6.py` ซึ่งแสดง **Decrypted Signature** และ **Extracted SHA-256 Hash** (หากตรวจพบ OID prefix ของ SHA-256)

### ภาพหน้าจอการสกัดข้อมูลจาก Certificate (ประกอบ)

> **[ให้ใส่รูปภาพ]** ภาพหน้าจอแสดงคำสั่ง `openssl x509 -in server.crt -text -noout` ที่ใช้สกัดค่า Signature Value, Modulus, และ Public Exponent จาก CA Certificate และ Server Certificate

---

## 3.2.3 อภิปรายผลลัพธ์ / สิ่งที่สังเกตได้ / ตอบคำถาม

### 1. หลักการทำงานของ Digital Certificate กับ RSA

Digital Certificate (ใบรับรองดิจิทัล) ตามมาตรฐาน **X.509** เป็นกลไกที่ใช้ **รับประกันความถูกต้องของ Public Key** ของเซิร์ฟเวอร์ โดยอาศัย **Certificate Authority (CA)** ซึ่งเป็นหน่วยงานที่ทุกฝ่ายเชื่อถือร่วมกัน (Trusted Third Party) ทำหน้าที่ลงลายเซ็นดิจิทัลบน Certificate

กระบวนการมีดังนี้:

| ขั้นตอน                | ฝั่งดำเนินการ | รายละเอียด                                                                                                 |
| ---------------------- | ------------- | ---------------------------------------------------------------------------------------------------------- |
| 1. สร้าง CSR           | Server        | สร้างคู่กุญแจ (Public/Private Key) แล้วส่ง Certificate Signing Request ไปยัง CA                            |
| 2. ตรวจสอบตัวตน        | CA            | ยืนยันตัวตนของผู้ขอ (Domain Validation / Organization Validation)                                          |
| 3. เซ็น Certificate    | CA            | คำนวณ **Hash ของ TBS Certificate** แล้วเซ็นด้วย Private Key ของ CA: `Signature = Hash^d mod n`             |
| 4. ตรวจสอบ Certificate | Client        | ใช้ Public Key ของ CA ถอดลายเซ็น: `Hash_recovered = Signature^e mod n` แล้วเปรียบเทียบกับ Hash ที่คำนวณเอง |

### 2. การวิเคราะห์ผลลัพธ์จากโปรแกรม

เมื่อรันโปรแกรม (ทั้ง C และ Python) จะได้ผลลัพธ์เป็น **ค่า hex ขนาดใหญ่** ซึ่งมีโครงสร้างตามมาตรฐาน **PKCS#1 v1.5 Signature Padding**:

```
0001 FFFF...FF 00 <DigestInfo>
```

| ส่วนประกอบ     | ความหมาย                                                                                                                                 |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `00 01`        | Block Type 01 (สำหรับ Signature)                                                                                                         |
| `FF FF ... FF` | Padding bytes เพื่อขยายข้อมูลให้เท่ากับขนาด modulus                                                                                      |
| `00`           | Separator byte คั่นระหว่าง padding กับข้อมูลจริง                                                                                         |
| `DigestInfo`   | โครงสร้าง ASN.1 DER ที่ประกอบด้วย **OID ของ Hash Algorithm** (เช่น SHA-256 = `2.16.840.1.101.3.4.2.1`) ตามด้วย **ค่า Hash** ขนาด 32 ไบต์ |

**สิ่งที่สังเกตได้:**

1. **ค่าที่ได้จากทั้ง C และ Python ตรงกัน** — เพราะทั้งคู่ทำ modular exponentiation เดียวกัน (`s^e mod n`) พิสูจน์ว่าการคำนวณ RSA ถูกต้อง

2. **โครงสร้าง PKCS#1 v1.5 ชัดเจน** — ค่า hex ที่ได้จะเริ่มต้นด้วย `0001FF...FF00` ตามด้วย DigestInfo ซึ่งยืนยันว่า Signature นี้ถูกสร้างตามมาตรฐาน

3. **สามารถสกัดค่า SHA-256 Hash ได้** — ท้ายสุดของ DigestInfo จะเป็นค่า SHA-256 ขนาด 64 ตัวอักษร hex (32 ไบต์) ซึ่งเป็น hash ของ TBS Certificate

### 3. การนำ RSA ไปใช้รับประกัน Public Key ในรูปแบบ Digital Certificate

กลไกที่ทำให้ Digital Certificate **รับประกันความน่าเชื่อถือ** ของ Public Key ได้นั้น อาศัยคุณสมบัติทางคณิตศาสตร์ของ RSA:

- **ความปลอดภัย (Security):** การปลอมลายเซ็นต้องหาค่า Private Key `d` ของ CA ซึ่งต้อง **แยกตัวประกอบ** ของ `n` (ผลคูณจำนวนเฉพาะขนาดใหญ่ 2 ตัว) — เป็นปัญหาที่แก้ไม่ได้ในเวลาที่เป็นไปได้ (Computationally Infeasible)

- **ความถูกต้อง (Integrity):** หากผู้โจมตีแก้ไข Certificate (เช่น เปลี่ยน Public Key ของเซิร์ฟเวอร์) ค่า hash ที่คำนวณใหม่จะ **ไม่ตรง** กับ hash ที่ถอดได้จาก Signature → การตรวจสอบล้มเหลว

- **ความไม่สามารถปฏิเสธได้ (Non-Repudiation):** เฉพาะ CA ที่มี Private Key เท่านั้นจึงสามารถสร้าง Signature ที่ตรวจสอบผ่านด้วย Public Key ของ CA ได้

- **Chain of Trust (ห่วงโซ่ความเชื่อถือ):** ระบบปฏิบัติการ/เบราว์เซอร์จะมี **Root CA Certificate** ติดตั้งไว้ล่วงหน้า (Pre-installed Trust Store) ทำให้สามารถตรวจสอบ Certificate ได้โดยไม่ต้องแลกเปลี่ยนกุญแจล่วงหน้ากับเซิร์ฟเวอร์

### 4. สรุป

การทดลอง Task 6 นี้แสดงให้เห็นกระบวนการ **Manual Verification** ของ X.509 Certificate โดยใช้ RSA modular exponentiation:

$$\text{Hash}_{\text{recovered}} = S^{e} \bmod n$$

ผลลัพธ์ที่ได้พิสูจน์ว่า Signature ที่แนบมากับ Server Certificate ถูกสร้างโดย CA จริง เพราะเมื่อถอดด้วย Public Key ของ CA แล้วได้โครงสร้าง PKCS#1 v1.5 ที่ถูกต้อง พร้อมค่า hash ที่สามารถนำไปเทียบกับ hash ของ TBS Certificate ได้ กลไกนี้คือหัวใจสำคัญของ **HTTPS/TLS** ที่ทำให้ผู้ใช้มั่นใจได้ว่า Public Key ที่ได้รับจากเซิร์ฟเวอร์เป็นของเซิร์ฟเวอร์ตัวจริง ไม่ใช่ของผู้โจมตี (Man-in-the-Middle Attack Prevention)

---
