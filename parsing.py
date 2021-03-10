import IPy
from pyparsing import *

with open(r'data/user.txt', 'r') as file:
    user_policy = file.read()
    with open(r'test.txt', 'r') as test_file:
        test = test_file.read()


# 通用匹配模式
integer = Word(nums)
identifier = Word(srange("[a-zA-Z_]"), srange("[a-zA-Z0-9_-]"))
ip_nosubnet = Combine(integer - ('.' + integer) * 3)
ip_subnet = Combine(integer - ('.' + integer) * 3 + "/" + integer)
ipaddress = ip_subnet ^ ip_nosubnet
# 用户匹配模式
vlan = "vlan" + integer
ip = "ip" + ipaddress
def_user = "user" + identifier + "{" + vlan + ";" + ip + ";" + "}"


result = def_user.parseString(test)
print(result)




