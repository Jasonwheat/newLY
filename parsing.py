import IPy
from pyparsing import *
from UNIT import *

with open(r'data/user.txt', 'r') as file:
    user_policy = file.read()

# 通用匹配模式
integer = Word(nums)
id = Word(srange("[a-zA-Z_]"), srange("[a-zA-Z0-9_-]"))
ip_subnet = Combine(integer - ('.' + integer) * 3)("address") + "/" + integer("num")
# 用户匹配模式
vlan = "vlan" + integer("vlan")
ip = ("ip" + ip_subnet("subnet"))
def_user = ("user" + id("name") + Suppress("{") + (
        (vlan + Suppress(";"))[..., 1] & (ip + Suppress(";"))[..., 1]) + Suppress("}"))
# 用户组匹配模式
user_schema = (Suppress("{") + (id("user*") + Suppress(";"))[...] + Suppress("}")) ^ \
              (Suppress("{") + (Suppress("user") + id("user*") + Suppress(";"))[...] + Suppress("}")) ^ \
              (Suppress("{") + Suppress("user") + (id("user*") + Suppress(","))[...] + id("user*") + Suppress(
                  ";") + Suppress("}"))
def_group = "group" + id("groupname") + user_schema
ip_range = "iprange" + Suppress("(") + Combine(integer - ('.' + integer) * 3)("address") + "/" + \
           (integer("num*") + Suppress(","))[...] + integer("num*") + Suppress(")") + user_schema
vlan_range = "vlanrange" + Suppress("(") + \
             integer("start_num") + Suppress("-") + integer("end_num") + Suppress(",") + integer("dif_num") + \
             Suppress(")") + user_schema
# ip网段匹配模式
# ipsegment p2 {10.168.4.80-10.168.5.254}
ip_nosubnet = Combine(integer - ('.' + integer) * 3)("address")
def_ipsegment = "ipsegment" + id("name") + Suppress("{") + ip_nosubnet("ip1") + Suppress("-") + ip_nosubnet(
    "ip2") + Suppress("}")

# 策略集匹配模式
# 隔离策略
iso_type1 = Group(
    Word("service") + id("servicetype") + Suppress(",") + Word("scrport") + integer("srcport") + Suppress(";"))
iso_type2 = Group(
    Word("protocol") + id("protocol") + Suppress(",") + Word("dstport") + integer("dstport") + Suppress(",") + Word(
        "scrport") + integer("srcport") + Suppress(";"))
p_isolate = "isolate" + Suppress("(") + (iso_type1[1, ...] & iso_type2[1, ...]) + Suppress(")") ^ \
            "isolate" + Suppress("(") + iso_type1[1, ...] + Suppress(")") ^ \
            "isolate" + Suppress("(") + iso_type2[1, ...] + Suppress(")") ^ \
            "isolate" + Suppress("(") + Suppress(")")

# linktype
p_link = (Word("link") + Word("vlan")("type*") + Suppress(";")) ^ \
         (Word("link") + Word("vxlan")("type*") + Suppress(";"))

# 网关
p_gateway = (Word("gateway") + (id("gateway*") + Suppress(","))[...] + id("gateway*") + Suppress(";"))

# 限速
bandwidth = integer("bw") + Suppress("M")
p_bandwidth = Word("bw") + bandwidth + Suppress(";")

# 陆航点
p_waypoint = Word("wp") + id("waypoint") + Suppress(";")

# acl偏好
acl_on = ("on" + (id("on*") + Suppress(","))[...] + id("on*"))
acl_under = ("under" + integer("under*"))
acl_moresafe = Word("moresafe")
acl_schema = (acl_on + Suppress(";"))[..., 1] & (acl_under + Suppress(";"))[..., 1] & (acl_moresafe + Suppress(";"))[
    ..., 1]
p_acl = ("acl" + Suppress("(") + acl_schema + Suppress(")"))

# 总定义
def_policy = "policy" + id("policy_name") + Suppress("{") + \
             ((p_isolate[..., 1]) & (p_link[..., 1]) & (p_gateway[..., 1]) & (p_bandwidth[..., 1]) & (p_acl[..., 1]) & (
                 p_waypoint[..., 1])) + \
             Suppress("}")

# 主函数匹配模式
main_policy_schema = id("policy_name*") + Suppress(";")
main_group_schema = id("group_name*") + (Suppress(",") + id("group_name*"))[...] + Suppress("apply") + id(
    "policy_name*") + Suppress(";")
main_direction_schema = id("group_name1*") + "->" + id("group_name2*") + Suppress("apply") + id(
    "policy_name*") + Suppress(";")
def_main = Suppress("main") + Suppress("{") + \
           (Group(main_policy_schema)[...] & Group(main_group_schema)[...] & Group(main_direction_schema)[...]) + \
           Suppress("}")


# 得到所有用户的方法
# 得到每个用户组的方法
global user_dict
user_dict = {}

# 返回一个字典：键为用户名，值为该用户的User对象
def get_user(data):
    for us in def_user.searchString(data):
        u = User()
        u.name = us["name"]
        for i in get_group(data):
            for j in get_group(data)[i].user_list:
                if u.name == j:
                    u.userG = i  # 遍历group字典获取用户组
        if "vlan" in us:
            u.vlan = int(us["vlan"])
        if 'ip' in list(us):
            u.ip = IP(IPy.IP(us["address"]), int(us["num"]))
        user_dict[us["name"]] = u
    # vlanrange分配
    v_list = sum(vlan_range.searchString(data))['user']
    start_num = int(sum(vlan_range.searchString(data))['start_num'])
    end_num = int(sum(vlan_range.searchString(data))['end_num'])
    dif_num = int(sum(vlan_range.searchString(data))['dif_num'])
    count = -1
    for v in v_list:
        count += 1
        for i in user_dict.keys():
            if v == i:
                user_dict[v].vlan = start_num + dif_num * count
    # iprange分配
    i_list = sum(ip_range.searchString(data))['user']

    num_list = sum(ip_range.searchString(data))['num']
    addr = sum(ip_range.searchString(data))['address']
    for iu in range(len(i_list)):
        user_dict[i_list[iu]].ip = IP(IPy.IP(addr), int(num_list[iu]))
    return user_dict


global group_dict
group_dict = {}


# 返回一个字典：键为用户组名，值为该用户组的UserGroup对象
def get_group(data):
    for gr in def_group.searchString(data):
        g = UserGroup()
        group_dict[gr["groupname"]] = g
        g.name = gr["groupname"]
        g.user_list = gr["user"]
    return group_dict


# 返回一个字典：键为ip网段名，值为ip网段
def get_ipsegment(data):
    ipsegment_dict = {}
    for ips in def_ipsegment.searchString(data):
        ipsegment_dict[ips["name"]] = [ips["ip1"], ips["ip2"]]
    return ipsegment_dict


# 所有定义的策略集
# 返回一个记录所有定义的策略集的字典，键为策略集名字，值为策略集具体信息
def get_policy(data):
    policy_dict = {}
    for po in def_policy.searchString(data):
        policy_dict[po["policy_name"]] = po
    # print(policy_dict.keys())
    return policy_dict


# 主函数调用策略
# 返回三个列表，分别是全局策略、多个用户组策略、方向性策略
def main_policy_called(data):
    global_plist = []  # 全局策略
    group_plist = []  # 多个用户组参与的策略
    direction_plist = []  # 方向性策略
    for i in sum(def_main.searchString(data)):
        if len(i) == 1:
            global_plist.append(i)
        else:
            group_plist.append(i)
    return global_plist, group_plist, direction_plist


# {'under': [], 'on': [], 'moresafe': 0}
# 返回一个记录acl偏好的字典
def acl_pref(data):
    acl_dict = {'under': [], 'on': [], 'moresafe': 0}
    policy = get_policy(data)
    for i in main_policy_called(data)[0]:
        list1 = list(policy[i[0]])
        if 'acl' in list1:
            if 'on' in list1:
                acl_dict['on'] = list(policy[i[0]]["on"])
            if 'under' in list1:
                acl_dict['under'] = list(policy[i[0]]["under"])
            if 'moresafe' in list1:
                acl_dict['moresafe'] = 1
    return acl_dict


# {'gateway': ['CE1', 'CE2'], 'Employee1': ['CE3']}
# 返回一个记录网关信息的字典，同时更新用户组字典中每个用户组对象的gateway变量
def gateway_set(data):
    gateway_dict = {'gateway': []}
    policy = get_policy(data)
    for i in main_policy_called(data)[0]:
        list1 = list(policy[i[0]])
        if 'gateway' in list1:
            gateway_dict['gateway'] = list(policy[i[0]]["gateway"])
    for i in main_policy_called(data)[1]:
        length = int(len(i))
        list1 = list(policy[i[length - 1]])
        if 'gateway' in list1:
            for j in range(length - 1):
                gateway_dict[i[j]] = list(policy[i[length - 1]]["gateway"])
                group_dict[i[j]].gateway = policy[i[length - 1]]["gateway"]
    return gateway_dict


# 更新用户组字典中每个用户组对象的linktype变量
def group_linktype(data):
    policy = get_policy(data)
    for i in main_policy_called(data)[1]:
        length = int(len(i))
        list1 = list(policy[i[length - 1]])
        if 'link' in list1:
            for j in range(length - 1):
                group_dict[i[j]].linktype = policy[i[length - 1]]["type"][0]


# def isolate_info_previous(data):
#     group_list = []
#     ipsegment_list = []
#     policy = get_policy(data)
#     for i in main_policy_called(data)[1]:
#         length = int(len(i))
#         list1 = list(policy[i[length - 1]])
#         if 'isolate' in list1:
#             flag = True  # flag为True代表isolate没有参数
#             for j in list1:
#                 if 'service' in list(j) or 'protocol' in list(j):
#                     flag = False
#                     break
#             if flag is True:
#                 if i[0] in get_group(data):
#                     group_list.append([i[0], i[1]])
#                 elif i[0] in get_ipsegment(data):
#                     ipsegment_list.append(get_ipsegment(data)[i[0]] + get_ipsegment(data)[i[1]])
#     return group_list, ipsegment_list


# 返回一个记录隔离信息类的对象的列表
def isolate_info(data):
    group_list = []
    ipsegment_list = []
    info_object_list = []
    policy = get_policy(data)
    for i in main_policy_called(data)[1]:
        length = int(len(i))
        list1 = list(policy[i[length - 1]])
        if 'isolate' in list1:
            # 隔离用户组和隔离网段部分代码
            flag = False  # flag为False代表isolate没有参数
            if i[0] in get_group(data):
                group_list.append([i[0], i[1]])
            elif i[0] in get_ipsegment(data):
                ipsegment_list.append(get_ipsegment(data)[i[0]] + get_ipsegment(data)[i[1]])
            for j in list1:
                if 'service' in list(j) or 'protocol' in list(j):
                    flag = True
                    break
            # acl拓展部分
            if flag is True:
                iso = IsolateInfo()
                if i[0] in get_group(data):
                    iso.group_info = [i[0], i[1]]
                elif i[0] in get_ipsegment(data):
                    iso.ipsegment_info = [i[0], i[1]]
                for j in list1:
                    if 'service' in list(j):
                        service_dict = {'service': j["servicetype"], 'srcport': int(j["srcport"])}
                        iso.service_info.append(service_dict)
                    if 'protocol' in list(j):
                        protocol_dict = {'protocol': j["protocol"], 'dstport': j["dstport"], 'srcport': j["srcport"]}
                        iso.protocol_info.append(protocol_dict)
                info_object_list.append(iso)
    return group_list, ipsegment_list, info_object_list


def bandwidth_info(data):
    pass


def waypoint_info(data):
    pass


def conflict(data):

    return True


# [['Employee1', 'Employee2']]
# [['10.168.4.80', '10.168.5.254', '10.168.100.90', '10.168.101.254']]

print("---------------------------")
print(get_group(user_policy))
print(get_user(user_policy))
# print(user_dict['A'].show())
# print(user_dict['C'].show())
# print(user_dict['D'].show())
# print(get_user(user_policy)[3].show())
print(get_ipsegment(user_policy))
print("---------------------------")
print(get_policy(user_policy).keys())
print(get_policy(user_policy))
print(main_policy_called(user_policy))
print("---------------------------")
print(isolate_info(user_policy)[0])
print(isolate_info(user_policy)[1])
print(isolate_info(user_policy)[2])
# print(isolate_info(user_policy)[0].show())
# print(isolate_info(user_policy)[1].show())
# print(acl_pref(user_policy))
# print(gateway_set(user_policy))
# print(group_linktype(user_policy))
# print(group_dict['G1'].gateway)
print("---------------------------")
