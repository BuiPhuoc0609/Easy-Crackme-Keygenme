# Easy-Crackme-Keygenme

## crackme1

### Static analysis

Đây là chương trình crackme yêu cầu nhập password:

<img width="1472" height="256" alt="image" src="https://github.com/user-attachments/assets/4e157ed4-3d8e-4f61-881d-c58fae855e50" />

main:

<img width="1918" height="1013" alt="image" src="https://github.com/user-attachments/assets/736782d1-2d27-4441-957a-22c7f7802f06" />

xem tiếp:

<img width="1918" height="1013" alt="image" src="https://github.com/user-attachments/assets/71729d5c-9cf7-4c57-a0c2-994a960fd0d2" />

<img width="1917" height="1012" alt="image" src="https://github.com/user-attachments/assets/4c067d74-a08b-46e4-bf5b-14d3b477b00a" />

ta có thể thấy đây là 1 bài dạng vm/state machine đơn giản check từng ký tự password, khi đúng hết sẽ in ra flag

### Dynamic analysis

Để hiểu rõ các case làm gì thì ta sẽ debug

Hàm `sub_B01000` đóng vai trò cấp phát vùng nhớ, decrypt shellcode và trả về địa chỉ shellcode để gọi hàm:

v5, v6 là hàm thuật toán mã hóa rc4:

<img width="826" height="122" alt="image" src="https://github.com/user-attachments/assets/ef2ce069-f82b-43c1-a277-f67368f6d950" />

<img width="1347" height="417" alt="image" src="https://github.com/user-attachments/assets/1461cf9f-00b9-4ac7-971d-c633e7216db0" />

<img width="1322" height="493" alt="image" src="https://github.com/user-attachments/assets/96ca3c88-8b45-447f-80ec-625ad272acb3" />

`case1` kiểm tra chẵn lẻ của input và xor, kiểu dữ kiệu 1 bytes:

<img width="787" height="286" alt="image" src="https://github.com/user-attachments/assets/c0fc1aa4-2de1-4815-90d6-1a581a800f3c" />

`case2` 5 lần đảo bit và xor `0x1693`, kiểu dữ liệu 2 bytes:

<img width="1337" height="486" alt="image" src="https://github.com/user-attachments/assets/141348ca-f6b4-4b7a-85de-6be0f6d3b7a6" />

`casse3` là mã hóa base64 với custom table:

<img width="1307" height="491" alt="image" src="https://github.com/user-attachments/assets/0512c9ec-78d5-44ed-85af-e29f12c15b8a" />

`case4` là mã hóa rc4 với key là `susan`:

<img width="1342" height="491" alt="image" src="https://github.com/user-attachments/assets/a0709219-6b32-4c11-8c95-600a70c42720" />

### Solve

Ta viết chương trình đảo ngược thuật toán để giải tìm password

```python
from Crypto.Cipher import ARC4
from Crypto.Util.number import*
import base64
password=[0]*0x126
#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
opcodes=[0x00000001, 0x00000000, 0xCCCCCC74, 0x00000001, 0x00000001, 0xCCCCCC48, 0x00000001, 0x00000002, 0xCCCCCC3B, 0x00000002, 0x00000088, 0xCCCC2481, 0x00000003, 0x0000006F, 0x6F593363, 0x00000002, 0x00000084, 0xCCCC0101, 0x00000002, 0x0000000A, 0xCCCCAF35, 0x00000001, 0x000000D0, 0xCCCCCC33, 0x00000003, 0x0000000F, 0x76784D64, 0x00000004, 0x00000012, 0x1AB120DD, 0x00000001, 0x00000106, 0xCCCCCC0C, 0x00000003, 0x000000E8, 0x3542446A, 0x00000002, 0x0000001D, 0xCCCC21A6, 0x00000002, 0x0000001F, 0xCCCC8ABE, 0x00000001, 0x00000021, 0xCCCCCC4C, 0x00000002, 0x00000022, 0xCCCC0E26, 0x00000001, 0x00000024, 0xCCCCCC35, 0x00000001, 0x0000005D, 0xCCCCCC3B, 0x00000003, 0x0000002B, 0x7539456A, 0x00000004, 0x00000016, 0x0DED3F88, 0x00000003, 0x000000EB, 0x7A56336A, 0x00000002, 0x00000032, 0xCCCCAF35, 0x00000002, 0x00000030, 0xCCCC2FAB, 0x00000002, 0x00000008, 0xCCCC3681, 0x00000003, 0x00000034, 0x75636C6A, 0x00000001, 0x00000037, 0xCCCCCC00, 0x00000002, 0x00000038, 0xCCCC3C25, 0x00000003, 0x00000053, 0x67524649, 0x00000001, 0x0000003E, 0xCCCCCC21, 0x00000001, 0x0000003F, 0xCCCCCC54, 0x00000001, 0x00000092, 0xCCCCCC37, 0x00000001, 0x00000086, 0xCCCCCC74, 0x00000004, 0x00000109, 0x13FD36C0, 0x00000001, 0x0000004A, 0xCCCCCC00, 0x00000001, 0x0000010D, 0xCCCCCC52, 0x00000004, 0x0000004D, 0x43BA3DC1, 0x00000003, 0x0000011C, 0x6F773264, 0x00000004, 0x0000003A, 0x0CB073CD, 0x00000004, 0x00000056, 0x06B973CD, 0x00000003, 0x0000005A, 0x796D3251, 0x00000004, 0x0000010F, 0x10AE36CB, 0x00000001, 0x0000005E, 0xCCCCCC3D, 0x00000002, 0x0000005F, 0xCCCC2101, 0x00000004, 0x00000068, 0x06B52788, 0x00000001, 0x000000BA, 0xCCCCCC44, 0x00000004, 0x0000009A, 0x06BA3ADC, 0x00000003, 0x0000006C, 0x6D4A4649, 0x00000004, 0x00000004, 0x43AE6288, 0x00000004, 0x00000072, 0x0EFD20C1, 0x00000002, 0x000000C7, 0xCCCC863D, 0x00000001, 0x0000007A, 0xCCCCCC2B, 0x00000004, 0x0000007B, 0x0DB82788, 0x00000001, 0x000000C6, 0xCCCCCC0E, 0x00000001, 0x00000083, 0xCCCCCC2B, 0x00000001, 0x00000003, 0xCCCCCC01, 0x00000004, 0x00000093, 0x13BC2388, 0x00000004, 0x000000A9, 0x43B23788, 0x00000003, 0x0000000C, 0x436D475A, 0x00000004, 0x0000008A, 0x11BC36CE, 0x00000004, 0x0000008E, 0x11BC73DB, 0x00000004, 0x000000AF, 0x0AB527D1, 0x00000002, 0x00000044, 0xCCCCA525, 0x00000001, 0x00000097, 0xCCCCCC37, 0x00000002, 0x00000098, 0xCCCC2F01, 0x00000004, 0x00000061, 0x02FD3CDC, 0x00000001, 0x0000009E, 0xCCCCCC52, 0x00000004, 0x0000009F, 0x3AFD7DDB, 0x00000004, 0x00000046, 0x17B126CB, 0x00000001, 0x000000A7, 0xCCCCCC33, 0x00000001, 0x0000002F, 0xCCCCCC00, 0x00000001, 0x00000087, 0xCCCCCC48, 0x00000001, 0x000000AD, 0xCCCCCC33, 0x00000001, 0x000000AE, 0xCCCCCC4E, 0x00000004, 0x000000C9, 0x00FD26C7, 0x00000002, 0x000000B3, 0xCCCCA122, 0x00000001, 0x000000B5, 0xCCCCCC00, 0x00000004, 0x000000B6, 0x43A83CD1, 0x00000003, 0x00000065, 0x73593351, 0x00000001, 0x000000BB, 0xCCCCCC37, 0x00000001, 0x000000BC, 0xCCCCCC31, 0x00000004, 0x000000D2, 0x0CA973DC, 0x00000003, 0x000000BF, 0x3842545A, 0x00000002, 0x000000C2, 0xCCCC2181, 0x00000001, 0x000000DA, 0xCCCCCC4E, 0x00000004, 0x0000007F, 0x17B430C9, 0x00000004, 0x00000076, 0x0FB821CD, 0x00000004, 0x000000FB, 0x11AD73CD, 0x00000002, 0x000000CD, 0xCCCC26A6, 0x00000001, 0x000000CF, 0xCCCCCC00, 0x00000002, 0x0000004B, 0xCCCC2C25, 0x00000001, 0x000000D1, 0xCCCCCC31, 0x00000002, 0x000000BD, 0xCCCC22A3, 0x00000003, 0x00000113, 0x796D4749, 0x00000002, 0x000000C4, 0xCCCCA426, 0x00000003, 0x000000EF, 0x6C6D476A, 0x00000004, 0x000000DC, 0x0DBC73CD, 0x00000001, 0x000000EE, 0xCCCCCC00, 0x00000004, 0x000000E4, 0x0CAF27C6, 0x00000003, 0x0000001A, 0x5539315A, 0x00000001, 0x0000002E, 0xCCCCCC35, 0x00000004, 0x000000E0, 0x0CBE73CC, 0x00000001, 0x000000DB, 0xCCCCCC35, 0x00000002, 0x000000F2, 0xCCCCA48C, 0x00000004, 0x000000F4, 0x07B33288, 0x00000002, 0x00000025, 0xCCCC39A7, 0x00000004, 0x00000040, 0x05B43788, 0x00000001, 0x000000FF, 0xCCCCCC3D, 0x00000003, 0x00000100, 0x6B563251, 0x00000003, 0x00000103, 0x6D4A5864, 0x00000004, 0x00000027, 0x3CBA1DC7, 0x00000002, 0x00000107, 0xCCCC062B, 0x00000004, 0x000000A3, 0x00FD26C7, 0x00000001, 0x000000A8, 0xCCCCCC4E, 0x00000001, 0x0000010E, 0xCCCCCC3D, 0x00000003, 0x000000F8, 0x67524649, 0x00000004, 0x000000D6, 0x02B53088, 0x00000002, 0x00000116, 0xCCCC8625, 0x00000004, 0x00000118, 0x0CFD20DC, 0x00000002, 0x00000051, 0xCCCCA2A8, 0x00000003, 0x0000011F, 0x33566C63, 0x00000003, 0x00000122, 0x6B4A5851, 0x00000001, 0x00000125, 0xCCCCCC0E]

def case1(a1, a2):
    v2=a2%2
    if v2==0:
        s=a2^0x20
    else:
        s=a2^0x52
    s=chr(s&0xff)
    print(s)
    password[a1]=s
def case2(a1,a2):
    v4=a2
    for i in range(5,0,-1):
        v4=(v4^0x1693)&0xffff
        v4=(((v4>>i)|(v4<<(16-i))))&0xffff
    #v4=((v4>>8)|(v4<<8))&0xffff
    s=long_to_bytes(v4).decode()
    print(s)
    password[a1]=s

def case3(a1,a2):
    normal="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    new=   "ABDCEHGFIJKLUNOPYRTSMVWXQZajcdefohibkmlngpqrstuv4xzy8123w56709+0"
    s=long_to_bytes(a2).decode()
    s2=''
    for i in s:
        n=new.index(i)
        s2+=normal[n]
    s=base64.b64decode(s2[::-1]).decode()
    print(s)
    password[a1]=s
def case4(a1,a2):
    cipher = ARC4.new(b"susan")
    s = cipher.decrypt(long_to_bytes(a2)[::-1]).decode()
    print(s)
    password[a1]=s
def sub_181080(a1, a2, a3):
    v4=[]
    if a1==1:
        case1(a2,a3)
    if a1==2:
        case2(a2,a3)
    if a1==3:
        case3(a2,a3)
    if a1==4:
        case4(a2,a3)


def sub_FC11D0():
    for i in range(0,122*3,3):
        sub_181080(opcodes[i], opcodes[i+1], opcodes[i+2])
sub_FC11D0()

for i in password:
    if i!=0:
        print(i,end='')
```
```
ThiS 1s A rIdiCuLously l0ng_Lon9_l0ng_loNg_lOng strIng. The most difficult thing is the decision to act, the rest is merely tenacity. The fears are paper tigers. You an do anything you decide to do. You an act to change and control your life; and the procedure, the process is its own reward.
```
Tuy bị thiếu vài chữ `c` nhưng vẫn có thể đoán được.

<img width="1462" height="445" alt="image" src="https://github.com/user-attachments/assets/143b9710-a08e-4091-81d8-d8fd0c00a7e2" />

flag: `vcstraining{Aw3s0me_D4ta_tran5Form4t1oN_Kak4}`







