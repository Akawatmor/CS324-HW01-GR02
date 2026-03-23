## Python3 Program to convert Hexadecimal to ASCII
# Function to convert Hexadecimal to ASCII
#
# For Example:
# 4120746f702073656372657421 -> A top secret!

x = input("Enter a Hexadecimal string: ")
ascii_string = bytes.fromhex(x).decode('utf-8')
print(ascii_string)
