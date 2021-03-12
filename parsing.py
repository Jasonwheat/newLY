import IPy
from pyparsing import *
from UNIT import User, IP

with open(r'data/user.txt', 'r') as file:
    user_policy = file.read()
with open(r'test.txt', 'r') as test_file:
    test = test_file.read()

# 通用匹配模式
integer = Word(nums)
id = Word(srange("[a-zA-Z_]"), srange("[a-zA-Z0-9_-]"))
ip_nosubnet = Combine(integer - ('.' + integer) * 3)
ip_subnet = Combine(integer - ('.' + integer) * 3 + "/" + integer)
ipaddress = ip_subnet ^ ip_nosubnet
# 用户匹配模式
vlan = "vlan" + integer("vlan")
ip = "ip" + ipaddress("ip")
def_user = ("user" + id("name") + Suppress("{") + (
        (vlan + Suppress(";"))[..., 1] & (ip + Suppress(";"))[..., 1]) + Suppress("}"))
# 用户组匹配模式
user_schema = (Suppress("{") + (id("user*") + Suppress(";"))[...] + Suppress("}")) ^ \
              (Suppress("{") + (Suppress("user") + id("user*") + Suppress(";"))[...] + Suppress("}")) ^ \
              (Suppress("{") + Suppress("user") + (id("user*") + Suppress(","))[...] + id("user*") + Suppress(
                  ";") + Suppress("}"))
def_group = "group" + id("groupname") + user_schema
ip_range = "iprange" + Suppress("(") + ip_subnet + Suppress(",") + integer + Suppress(")") + user_schema
vlan_range = "vlanrange" + Suppress("(") + integer("start_num") + Suppress("-") + integer("end_num") + Suppress(",") + integer("dif_num") + Suppress(
    ")") + user_schema

# 策略组匹配模式
protocol = "FTP"
time = Combine(Combine(integer + ":" + integer) + "-" + Combine(integer + ":" + integer))
policy_isolate = "isolate" + Suppress("(") + "type" + protocol + Suppress(";") + "time" + time + Suppress(
    ";") + Suppress(")")
policy = "policy" + id + Suppress("{") + policy_isolate[...] + Suppress("}")


# 得到所有用户的方法
# 得到每个用户组的方法
def get_user(data):
    user_list = []
    for us in def_user.searchString(data):
        u = User()
        u.name = us["name"]
        for i in get_group(data):
            for j in get_group(data)[i]:
                if u.name == j:
                    u.userG = i  # 遍历group字典获取用户组
        if "vlan" in us:
            u.vlan = int(us["vlan"])
        if "ip" in us:
            u.ip = us["ip"]
        user_list.append(u)
    # vlanrange分配
    v_list = sum(vlan_range.searchString(data))['user']
    start_num = int(sum(vlan_range.searchString(data))['start_num'])
    end_num = int(sum(vlan_range.searchString(data))['end_num'])
    dif_num = int(sum(vlan_range.searchString(data))['dif_num'])
    count = -1
    for v in v_list:
        count += 1
        for i in user_list:
            if v == i.name:
                i.vlan = start_num + dif_num * count

    return user_list


# 返回一个字典：键为用户组名，值为该用户组下的用户列表
def get_group(data):
    group_dict = {}
    for gr in def_group.searchString(data):
        group_dict[gr["groupname"]] = gr["user"]
    return group_dict


s7 = "user A {ip 192.168.12.1/24; vlan 10; } " \
     "user B { vlan 10; ip 192.168.12.1/24; } " \
     "user C { vlan 10; } " \
     "user D {ip 192.168.12.1/24; } " \
     "group G1{A;C;} " \
     "group G2{user V; user C;} " \
     "group G3{user x;} " \
     "iprange(192.160.0.0/16,24){user C,D;} " \
     "vlanrange(30-100,1){user C; user D;} " \
     "isolate(type FTP;time 0:00-8:00;)"

# print(ip_range.parseString(s9))
# print(vlan_range.searchString(s7))
# print(sum(vlan_range.searchString(s7))['user'])
# print(sum(vlan_range.searchString(s7))['dif_num'])
print(sum(policy_isolate.searchString(s7)))


print(get_user(s7))
print(get_user(s7)[2].show())
# print(get_group(s7)['G1'][0])
# print(get_group(s7))


