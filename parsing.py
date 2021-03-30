import IPy
from pyparsing import *
from UNIT import *

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
vlan_range = "vlanrange" + Suppress("(") + \
             integer("start_num") + Suppress("-") + integer("end_num") + Suppress(",") + integer("dif_num") + \
             Suppress(")") + user_schema

# 策略集匹配模式
protocol = "FTP"
time = Combine(Combine(integer + ":" + integer) + "-" + Combine(integer + ":" + integer))
p_isolate = "isolate" + Suppress("(") + "type" + protocol + Suppress(",") + "time" + time + Suppress(")") + Suppress(
    ";")
p_link = (Word("link") + "vlan" + Suppress(";")) ^ \
         (Word("link") + "vxlan" + Suppress(";"))
p_gateway = "gateway" + id("gateway") + Suppress(";")
bandwidth = integer("bw") + Suppress("M")
p_bandwidth = "BW" + bandwidth + Suppress(";")
p_acl = "acl" + Suppress("(") + \
        (("on" + id + Suppress(";")) & ("under" + integer + Suppress(";")) & ("moresafe" + Suppress(";"))) + \
        Suppress(")")
def_policy = "policy" + id("policy_name") + Suppress("{") + \
             ((p_isolate[..., 1]) & (p_link[..., 1]) & (p_gateway[..., 1]) & (p_bandwidth[..., 1])) & (p_acl[..., 1]) + \
             Suppress("}")

# 主函数匹配模式
main_policy_schema = id("policy_name*") + Suppress(";")
main_group_schema = id("group_name*") + (Suppress(",") + id("group_name*"))[...] + Suppress("apply") + id(
    "policy_name*") + Suppress(";")
def_main = Suppress("main") + Suppress("{") + (
            Group(main_policy_schema)[...] & Group(main_group_schema)[...]) + Suppress("}")


# 得到所有用户的方法
# 得到每个用户组的方法
def get_user(data):
    user_list = []
    for us in def_user.searchString(data):
        u = User()
        u.name = us["name"]
        for i in get_group(data):
            for j in get_group(data)[i].user_list:
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


# 返回一个字典：键为用户组名，值为该用户组对象
def get_group(data):
    group_dict = {}
    for gr in def_group.searchString(data):
        g = UserGroup()
        group_dict[gr["groupname"]] = g
        g.name = gr["groupname"]
        g.user_list = gr["user"]
    return group_dict


def get_policy(data):
    policy_dict = {}
    for po in def_policy.searchString(data):
        policy_dict[po["policy_name"]] = po
    return policy_dict


# 将主函数调用的策略存起来
def main_policy_called(data):
    global_plist = []
    group_plist = []
    for i in sum(def_main.searchString(data)):
        print(i)
        group_plist.append(i)
    print(group_plist)
    print(group_plist[0])


s = "main { " \
    "A,B apply linktype_vlan;" \
    "traffic_limit;" \
    "A apply a;" \
    "}"
s7 = "user A {ip 192.168.12.1/24; vlan 10; } " \
     "user B { vlan 10; ip 192.168.12.1/24; } " \
     "user C { vlan 10; } " \
     "user D {ip 192.168.12.1/24; } " \
     "group G1{A;C;} " \
     "group G2{user V; user C;} " \
     "group G3{user x;} " \
     "iprange(192.160.0.0/16,24){user C,D;} " \
     "vlanrange(30-100,1){user C; user D;} " \
     "isolate(type FTP;time 0:00-8:00;)" \
     "policy a{ " \
     "link vlan; " \
     "gateway CE;" \
     "}" \
     "policy b { " \
     "isolate(type FTP,time 0:00-8:00); " \
     "link vxlan;" \
     "}" \
     "policy traffic_limit {" \
     "BW 2M; " \
     "} " \
     "policy ACL {" \
     "acl(on CE1;under 30; moresafe;)" \
     "}"

print(def_policy.searchString(s7))
print(get_policy(s7))
print("---------------------------")
print(main_policy_called(s))
print("---------------------------")

print(get_group(s7))
print(get_user(s7))
print(get_user(s7)[2].show())
print(get_user(s7)[3].show())
