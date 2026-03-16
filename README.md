# CS324 Lab 1 (Cryptography / RSA)

แลปนี้เป็นการทดลองใช้งาน RSA ด้วย OpenSSL BIGNUM ในภาษา C ครอบคลุมการหา private key, encryption/decryption, digital signature และการตรวจสอบลายเซ็นในแนวคิด X.509

## โครงสร้างไฟล์หลัก

- `no1.c` : หา RSA private key `d` จากค่า `p`, `q`, `e`
- `no2.c` : เข้ารหัสข้อความด้วย public key (`C = M^e mod n`)
- `no3.c` : ถอดรหัสข้อความด้วย private key (`M = C^d mod n`)
- `no4.c` : สร้างลายเซ็นดิจิทัลจากข้อความ 2 ชุดแล้วเปรียบเทียบผล
- `no5.c` : ตรวจสอบผลของการแก้ไข signature (original vs corrupted)
- `no6.c` : ทดลอง verify แนวคิด certificate signature แบบ manual ด้วย `S^e mod n`
- `bn_sample.c` : ตัวอย่างการใช้งาน BIGNUM เบื้องต้น

## ความต้องการระบบ

- Linux
- GCC
- OpenSSL development package (มี `openssl/bn.h` และ libcrypto)

ตัวอย่างติดตั้งบน Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev
```

## วิธีคอมไพล์

คอมไพล์ทีละไฟล์:

```bash
gcc -o no1 no1.c -lcrypto
gcc -o no2 no2.c -lcrypto
gcc -o no3 no3.c -lcrypto
gcc -o no4 no4.c -lcrypto
gcc -o no5 no5.c -lcrypto
gcc -o no6 no6.c -lcrypto
```

หรือคอมไพล์ตัวอย่าง:

```bash
gcc -o bn_sample bn_sample.c -lcrypto
```

## วิธีรัน

```bash
./no1
./no2
./no3
./no4
./no5
./no6
```

แต่ละโปรแกรมจะพิมพ์ผลลัพธ์เป็นเลขฐาน 16 (Hex)

## หมายเหตุเรื่องไฟล์ PEM

ไฟล์ `.pem` ในแลปนี้ใช้เป็น **public key ที่ extract มาเพื่อการทดลอง/การเรียนรู้** เท่านั้น

- ไม่ใช่ความลับ
- ไม่ต้องกังวลประเด็น secure storage ในขอบเขตงานนี้

## หมายเหตุเพิ่มเติมของ Task 6

ใน `no6.c` มีค่าคงที่สำหรับ `n_ca`, `e_ca`, `signature` ที่ใช้ทดลอง verify แบบ manual

- หากอาจารย์ให้ข้อมูลชุดใหม่ สามารถแก้ค่า Hex ได้โดยตรงในโค้ด
- หลักการยังเหมือนเดิม: คำนวณ `S^e mod n` แล้วเทียบโครงสร้างผลลัพธ์กับข้อมูลที่คาดหวัง
