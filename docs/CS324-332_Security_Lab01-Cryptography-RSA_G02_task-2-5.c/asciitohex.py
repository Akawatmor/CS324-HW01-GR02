## Python3 Program to convert ASCII to Hexadecimal
# Function to convert ASCII to Hexadecimal
#
# For Example:
# A top secret! -> 4120746f702073656372657421
x = input("Enter a Ascii string: ")
print(x.encode().hex())