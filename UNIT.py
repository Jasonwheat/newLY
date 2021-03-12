#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
常用的数据结构
"""
from z3 import *
import IPy


class User:
    """
    用户节点数据结构
    """

    def __init__(self):
        self.name = ''
        self.userG = ''
        self.access = ''
        self.vlan = 0
        self.ip = None
        self.num = 1

    def getUser(self):
        pass

    def show(self):
        print("--------")
        print("name:" + self.name)
        print("group:" + self.userG)
        print("access:" + self.access)
        print("vlan:" + str(self.vlan))
        print("ip:" + str(self.ip))
        print("num:" + str(self.num))
        print("--------")


class AggUsers:
    """
    聚合用户节点
    """

    def __init__(self):
        self.name = ''
        self.userG = ''
        self.access = ''
        self.vlan = 0
        self.ip = None
        self.users_list = []

    def setFromaggUser(self, user_dict_key, user_dict_value):
        # user_dict是被处理过的
        self.userG = user_dict_key[0]
        self.access = user_dict_key[1]
        self.vlan = user_dict_key[2]
        self.name = user_dict_key[0] + user_dict_value[0].name
        for user in user_dict_value:
            self.users_list.append(user)


def aggUser(user_list):
    """
    对用户节点的一种聚集，聚集原则：
    （同一用户组--同一接入节点--同一vlan，
    在不考虑ACL的前提下，所聚集的用户节点要具有相同的流量路径）
    用于精简构建网络流量模型的规模
    输入：用户节点(User)列表
    输出：用户节点（聚合后）列表
    """
    key = []  # 分类
    agg_dict = {}  # 分类存储
    agg_user_node = []  # output
    for user in user_list:
        tem_key = (user.userG, user.access, user.vlan)
        if tem_key not in key:
            key.append(tem_key)
            agg_dict[tem_key] = []
            agg_dict[tem_key].append(user)
        else:
            agg_dict[tem_key].append(user)
    for agg_user in agg_dict:
        tem_aggusers = AggUsers()
        tem_aggusers.setFromaggUser(agg_user, agg_dict[agg_user])
        agg_user_node.append(tem_aggusers)
    return agg_user_node


class IP:
    """
    IP数据结构，使用int（十进制）保存
    格式：fst.snd.trd.fth/mask
    通过getIP读取字符串格式IP，并检查IP格式是否符合标准
    """

    # def __init__(self, ip_instance, prefix_len):
    #     self.ip_address = ip_instance
    #     self.prefix_len = prefix_len
    #     self.prefix = self.ip_address.make_net(prefix_len)

    def __init__(self, ip_instance: IPy.IP, prefix_len: int = -1):
        self.ip_address = ip_instance
        if prefix_len == -1:
            self.prefix_len = ip_instance.prefixlen()
        else:
            self.prefix_len = prefix_len
        self.prefix = self.ip_address[0].make_net(self.prefix_len)

    def __hash__(self):
        return self.ip_address.__hash__()

    def __repr__(self):
        return "IP('%s')" % (self.ip_address.strCompressed(1))

    def __eq__(self, other):
        if not isinstance(other, IP):
            return False
        return self.ip_address.__cmp__(other.ip_address) == 0

    # def Str2int_ip(self, str):
    #     tem_int = int(str)
    #     assert (0 <= tem_int <= 255)
    #     return tem_int
    #
    # def Str2int_mask(self, str):
    #     tem_int = int(str)
    #     assert (0 <= tem_int <= 32)
    #     return tem_int
    #
    # def get_IP_no_mask(self, nomask_IP_Str):
    #     tem_str = [''] * 4
    #     k = 0
    #     for char in nomask_IP_Str:
    #         if char == '.':
    #             k += 1
    #             continue
    #         tem_str[k] += char
    #     self.fst = self.Str2int_ip(tem_str[0])
    #     self.snd = self.Str2int_ip(tem_str[1])
    #     self.trd = self.Str2int_ip(tem_str[2])
    #     self.fth = self.Str2int_ip(tem_str[3])
    #     self.strip = tem_str[0] + '.' + tem_str[1] + '.' + tem_str[2] + '.' + tem_str[3]
    #
    #
    # def getIP(self,IP_Str):
    #     tem_str = [''] * 5
    #     k = 0
    #     for char in IP_Str:
    #         if (char == '.'or char == '/'):
    #             k += 1
    #             continue
    #         tem_str[k] += char
    #     self.fst = self.Str2int_ip(tem_str[0])
    #     self.snd = self.Str2int_ip(tem_str[1])
    #     self.trd = self.Str2int_ip(tem_str[2])
    #     self.fth = self.Str2int_ip(tem_str[3])
    #     self.mask = self.Str2int_mask(tem_str[4])
    #     self.strip = tem_str[0] + '.' + tem_str[1] + '.' + tem_str[2] + '.' + tem_str[3] + '/' + tem_str[4]


class Segment_IP:
    """
    分段IP
    """

    def __init__(self):
        self.start_IP = IP()
        self.end_IP = IP()

    def getFromInput(self, str):
        pass


def aggIP(ip_list):
    """
    寻找ip组的最小掩码ip。eg 10.10.10.1/24 and 10.10.10.2/24 为10.10.
    :param ip_list:
    :return:
    """


class Traffic:
    """
    流量模型
    srcIP（key）
    dstIP（key）
    srcUser
    dstUser
    srcVlan
    dstVlan
    """

    def __init__(self):
        self.srcIP = None
        self.dstIP = None
        self.srcUser = ''
        self.dstUser = ''
        self.srcVlan = 0
        self.dstVlan = 0

    def getFromaggUser(self):
        pass


'''
    def set_device_interface_ip(self):
        for (source, target, dir) in self.ans_topo.edges.data():
            if not self.device_is_user_node(source) and not self.device_is_user_node(target):
                if 'prefix' not in self.ans_topo[target][source]:
                    prefix = L2.get_a_prefix()
                    if 'interface' not in self.ans_topo.nodes[source]:
                        self.ans_topo.nodes[source]['interface'] = {}
                    self.ans_topo.nodes[source]['interface'].update(
                        {self.ans_topo[source][target]['int']: L2.get_a_ip_in_prefix(prefix)})
                    self.ans_topo[source][target]['prefix'] = prefix
                else:
                    if 'interface' not in self.ans_topo.nodes[source]:
                        self.ans_topo.nodes[source]['interface'] = {}
                    self.ans_topo.nodes[source]['interface'].update(
                        {self.ans_topo[source][target]['int']:
                             L2.get_a_ip_in_prefix(self.ans_topo[target][source]['prefix'])})
'''