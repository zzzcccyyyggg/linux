def to_signed_64(num):
    return num - 0x10000000000000000 if num >= 0x8000000000000000 else num
num2 = 13957078615809569752
signed_num2 = to_signed_64(num2)
print(signed_num2)  # 输出 -4980116957444261279