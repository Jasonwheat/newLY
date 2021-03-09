import IPy
from pyparsing import *

with open(r'data/user.txt', 'r') as file:
    user_policy = file.read()


# 通用匹配模式
integer = Word(nums)
identifier = Word(srange("[a-zA-Z_]"), srange("[a-zA-Z0-9_-]"))
ipaddress = Combine(integer - ('.' + integer) * 3)

str = "999"
result = integer.parseString(str)
print(result)

data = '''
user A{vlan 10;ip 192.168.10.0/24;}
user B{vlan 20;ip 192.168.20.0/24;}
vlanrange(30-100,1){user C; user D;}
'''




