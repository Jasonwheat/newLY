import ply.lex as lex
import IPy

# read files
with open(r'data/user.txt', 'r') as file:
    user_policy = file.read()

reserved = {
    'user': 'USER',
    'group': 'GROUP',
    'ip': 'IP',
    'vlan': 'VLAN',
    'iprange': 'IPRANGE',
    'vlanrange': 'VLANRANGE',
}

tokens = [
    'NUMBER',
    'IPADDRESS',
    'IPADDRESS_SUBNET',
    'IDENTIFIER',
    'LPAREN',
    'RPAREN',
    'LBRAKET',
    'RBRAKET',
    'LBRACE',
    'RBRACE',
    'SEMICOLON',
    'HYPHEN',
    'COMMA',
] + list(reserved.values())


# Regular expression rules for simple tokens
t_LPAREN = r'\('
t_RPAREN = r'\)'
t_LBRAKET = r'\['
t_RBRAKET = r'\]'
t_LBRACE = r'\{'
t_RBRACE = r'\}'
t_SEMICOLON = r';'
t_HYPHEN = r'-'
t_COMMA = r','


# A regular expression rule with some action code
def t_IPADDRESS_SUBNET(t):
    r'(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])/(\d+)'
    # t.value = IPy.IP(t.value)
    return t


def t_IPADDRESS(t):
    r'(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])'
    # t.value = IPy.IP(t.value)
    return t


def t_NUMBER(t):
    r'\d+'
    t.value = int(t.value)
    return t


def t_IDENTIFIER(t):
    r'[a-zA-Z_][a-zA-Z_0-9]*'
    t.type = reserved.get(t.value, 'IDENTIFIER')
    return t


# Define a rule so we can track line numbers
def t_newline(t):
    r'\n+'
    t.lexer.lineno += len(t.value)


# A string containing ignored characters (spaces and tabs)
t_ignore = ' \t'


# Error handling rule
def t_error(t):
    print("Illegal character '%s'" % t.value[0])
    t.lexer.skip(1)


# Build the lexer
lexer = lex.lex()

data = '''
user A{vlan 10;ip 192.168.10.0/24;}
user B{vlan 20;ip 192.168.20.0/24;}
vlanrange(30-100,1){user C; user D;}
'''
# data2 = user_policy

lexer.input(data)
while True:
    tok = lexer.token()
    if not tok:
        break
    print(tok)

# 规约：使用一个产生式的左部替代右部


