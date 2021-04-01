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
p_isolate = "isolate" + Suppress("(") + "type" + protocol + Suppress(";") + "time" + time + Suppress(")") + Suppress(
    ";")

p_link = (Word("link") + "vlan" + Suppress(";")) ^ \
         (Word("link") + "vxlan" + Suppress(";"))

p_gateway = Word("gateway") + id("gateway") + Suppress(";")

bandwidth = integer("bw") + Suppress("M")
p_bandwidth = Word("bw") + bandwidth + Suppress(";")

p_waypoint = Word("wp") + id("waypoint") + Suppress(";")

acl_on = ("on" + (id + Suppress(","))[...] + id)
acl_under = ("under" + integer)
acl_moresafe = Word("moresafe")
acl_schema = (acl_on + Suppress(";"))[..., 1] & (acl_under + Suppress(";"))[..., 1] & (acl_moresafe + Suppress(";"))[..., 1]
p_acl = ("acl" + Suppress("(") + acl_schema + Suppress(")"))

def_policy = "policy" + id("policy_name") + Suppress("{") + \
             ((p_isolate[..., 1]) & (p_link[..., 1]) & (p_gateway[..., 1]) & (p_bandwidth[..., 1]) & (p_acl[..., 1]) & (p_waypoint[..., 1])) + \
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
    print(policy_dict.keys())
    return policy_dict


# 将主函数调用的策略存起来
# 全局策略和用户组策略
def main_policy_called(data):
    global_plist = []
    group_plist = []
    for i in sum(def_main.searchString(data)):
        if len(i) == 1:
            global_plist.append(i)
        else:
            group_plist.append(i)
    return global_plist, group_plist


# {'under': [], 'on': [], 'moresafe': 0}
def acl_pref(data):
    acl_dict = {'under': [], 'on': [], 'moresafe': 0}
    if main_policy_called(data)[0]:
        pass


# {'gateway': ['CE1', 'CE2'], 'Employee1': ['CE3']}
def gateway_set(data):
    pass

# [['Employee1', 'Employee2']]
# [['10.168.4.80', '10.168.5.254', '10.168.100.90', '10.168.101.254']]


print(get_group(user_policy))
print(get_user(user_policy))
print(get_user(user_policy)[2].show())
print(get_user(user_policy)[3].show())
print("---------------------------")
print(get_policy(user_policy))
print("---------------------------")
print(main_policy_called(user_policy)[0])
print(main_policy_called(user_policy)[1])
print("---------------------------")
