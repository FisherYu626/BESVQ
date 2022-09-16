import numpy as np
import time
import sys
import datetime
import os
from scipy.sparse import csr_matrix
import re
import random
import hmac
import random
import pickle
from Crypto.Cipher import AES
import json
import string
from web3 import Web3
import json
from web3.middleware import geth_poa_middleware


sys.setrecursionlimit(10000) # 设置递归深度

w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)
print(w3.eth.blockNumber)

#读取kw-file关系
f_Kw_File_Use = open('Kw_File_Use.txt','rb')
Kw_File_Use=pickle.load(f_Kw_File_Use)

#私钥

secreat_key=hmac.new(b'chen').digest()
model = AES.MODE_ECB

#######################################################建立索引####################################################
def Build_index(Kw_File_Use):
    ##################################client端私钥
    secreat_key=hmac.new(b'chen').digest()
    # print(secreat_key)
    model = AES.MODE_ECB

    ##################################建server端索引
    server_index={}      #server索引
    blockchain_index={}  #发给blockchain的索引
    client_index={}  #client索引yes
    w_f_addr_table={}

    for kw in Kw_File_Use:
        ################################################################################################生成客户端索引
        start_file_id = Kw_File_Use[kw][len(Kw_File_Use[kw]) - 1]  # client存储的首文件id
        # print(start_file_id)
        # 计算首文件地址
        str1 = kw + start_file_id # w||f_i
        st = str1.encode('utf-8')  # 连接的字符串
        # print(st)
        addr = hmac.new(st)
        start_file_addr = addr.digest()  # client存储的首文件地址 F(w||f_i)
        server_upt_time = 0  # server 更新次数 u
        block_upt_time = 0  # blockchain 更新次数 v
        search_or_not = 0  # 是否搜索过 s
        client_index[kw] = [server_upt_time, block_upt_time, search_or_not, start_file_addr]
        ################################################################################################生成token
        # client生成token（server端文件地址+文件内容）
        #字符串连接
        tok_server_addr = (kw + str(server_upt_time) + str(1)).zfill(16)  # w||u||1
        tok_server_enc = (kw + str(server_upt_time) + str(2)).zfill(16)  # w||u||2
        tok_block=(kw+str(block_upt_time)).zfill(16) # w||v

        #转字节
        t_addr = tok_server_addr.encode('utf-8') 
        t_enc = tok_server_enc.encode('utf-8')
        t_blo=tok_block.encode('utf-8')
        #加密生成token
        aes = AES.new(secreat_key, model) 
        # 生成token
        Toekn_S_Addr = aes.encrypt(t_addr) # t_w^1 = G(k,w||u||1)
        Toekn_S_Enc = aes.encrypt(t_enc) # t_w^2 = G(k,w||u||2)
        Token_block=aes.encrypt(t_blo) # l_w = G(k,w||v)


        for i in range(len(Kw_File_Use[kw])):
           if i==0:  #nonce块
               ###############生成当前文件地址
               str1 = kw.encode('utf-8') + Kw_File_Use[kw][0]    # w||\alpha_w
               addr = hmac.new(str1)
               addr_file = addr.digest()    # nonce = F(w||\alpha_w)
               w_f_addr_table[kw]=[addr_file]

               ################生成当前G
               # G(t1w,ptr n)
               aes_t1 = AES.new(Toekn_S_Addr, model)    
               G_token_S_addr = aes_t1.encrypt(addr_file) # P_0 = G(t_w^1,nonce)
               # G(t2w,ptr n)
               aes_t2 = AES.new(Toekn_S_Enc, model)
               G_token_S_enc = aes_t2.encrypt(addr_file) # V_0 = G(t_w^2,ptr_1)


               #####异或下一文件地址，所有nonce块都异或b'NNNNNNNNNNNNNNNN'
               addr=bytes(a ^ b for a, b in zip(G_token_S_addr, b'NNNNNNNNNNNNNNNN'))
               #####与nonce值异或
               enc_nonce=bytes(a ^ b for a, b in zip(G_token_S_enc, Kw_File_Use[kw][0] ))    #与nonce直接异或
               server_index[addr_file]=[addr, enc_nonce]   #server端nonce块的数据
               #blockchain_index为每个token-所有文件hash的异或
               # print("Kw_File_Use[kw][0]")
               # print(Kw_File_Use[kw][0])
               # hashnonce=hmac.new(Kw_File_Use[kw][0]).digest()
               hashnonce=Web3.keccak(Kw_File_Use[kw][0]) #############################
               # print("hashnonce")
               # print(hashnonce)
               blockchain_index[Token_block]=hashnonce
           else:
               #获得地址
               file_id = Kw_File_Use[kw][i]  # 对应文件名字  
               str1 = kw + file_id  # 连接的字符串 w||f_i
               st = str1.encode('utf-8')  # 转字节
               addr = hmac.new(st)
               addr_file = addr.digest()  # ptr_1 = F(w||f_1)
               w_f_addr_table[kw].append(addr_file)

               ################生成当前G
               # G(t1w,ptr n)
               aes_t1 = AES.new(Toekn_S_Addr, model)
               G_token_S_addr = aes_t1.encrypt(addr_file) # G(t_w^1,ptr_1)
               # G(t2w,ptr n)
               aes_t2 = AES.new(Toekn_S_Enc, model)
               G_token_S_enc = aes_t2.encrypt(addr_file) # G(t_w^2,ptr_1)
               #####异或下一文件地址，所有nonce块都异或前一个块
               #上一文件地址
               last_file_addr=w_f_addr_table[kw][i-1]
               #异或上一文件地址
               addr = bytes(a ^ b for a, b in zip(G_token_S_addr, last_file_addr)) # P_1 = G(t_w^1,ptr_1) \xor ptr_0

               #获得文件ID的密文 Enc(k,fi)
               m=Kw_File_Use[kw][i]
               fileID_en=m.encode('utf-8')
               # print(fileID_en)
               enc_file_ID=aes.encrypt(fileID_en) # C_f

               enc_file = bytes(a ^ b for a, b in zip(G_token_S_enc, enc_file_ID))  # 与nonce直接异或 V_1 = G(t_w^2,ptr_1) \xor C_f
               server_index[addr_file] = [addr, enc_file]  # server端nonce块的数据
               #blockchain index 累计异或
               #当前密文的hash,对文件id密文hash
               # hash_fileID=hmac.new(enc_file_ID).digest()

               hash_fileID=Web3.keccak(enc_file_ID) #############################

               # # blockchain_index[dd]=cc.decode()
               # # blockchain_index[Token_block.decode()] = bytes(a ^ b for a, b in zip(blockchain_index[Token_block],hash_fileID)).decode()
               blockchain_index[Token_block]=bytes(a ^ b for a, b in zip(blockchain_index[Token_block],hash_fileID))

    return server_index,blockchain_index,client_index






##################################################################搜索

#确定要搜索的kw，以及发送到server和blockchain的token




def user_search_keyword(client_index):

    # inputKW=input("请输入要搜索的关键字")
    inputKW="chen"
    server_upt_time, block_upt_time, search_or_not, start_file_addr=client_index[inputKW]

    #判断这个关键字在server上之前是否换过toekn

    # if server_upt_time==0:
        ## 生成搜索token
    tok_server_addr = (inputKW + str(server_upt_time) + str(1)).zfill(16)  # w||u||1
    # print(tok_server_addr)
    tok_server_enc = (inputKW + str(server_upt_time) + str(2)).zfill(16)  # w||u||2
    # print(tok_server_enc)
    tok_block = (inputKW + str(block_upt_time)).zfill(16)    #w||v
    # print(tok_block)
    t_addr = tok_server_addr.encode('utf-8')
    t_enc = tok_server_enc.encode('utf-8')
    t_blo = tok_block.encode('utf-8')
    aes = AES.new(secreat_key, model)
    Toekn_S_Addr = aes.encrypt(t_addr)
    Toekn_S_Enc = aes.encrypt(t_enc)
    Token_block = aes.encrypt(t_blo)
    # client_index[inputKW][search_or_not]=1  #设为搜索过
    client_index[inputKW][2] = 1
    return Toekn_S_Addr,Toekn_S_Enc,Token_block,start_file_addr


########################################用户搜索###############################
def user_search_keyword_mutiple(client_index,inputKW):

    # inputKW="chen"
    server_upt_time, block_upt_time, search_or_not, start_file_addr=client_index[inputKW]

    #判断这个关键字在server上之前是否换过toekn

    # if server_upt_time==0:
        ## 生成搜索token
    tok_server_addr = (inputKW + str(server_upt_time) + str(1)).zfill(16)  # w||u||1
    # print(tok_server_addr)
    tok_server_enc = (inputKW + str(server_upt_time) + str(2)).zfill(16)  # w||u||2
    # print(tok_server_enc)
    tok_block = (inputKW + str(block_upt_time)).zfill(16)    #w||v
    # print(tok_block)
    t_addr = tok_server_addr.encode('utf-8')
    t_enc = tok_server_enc.encode('utf-8')
    t_blo = tok_block.encode('utf-8')
    aes = AES.new(secreat_key, model)
    Toekn_S_Addr = aes.encrypt(t_addr) # G(k,w||u||1)
    Toekn_S_Enc = aes.encrypt(t_enc) # G(k,w||u||2)
    Token_block = aes.encrypt(t_blo) # G(k,w||v)
    # client_index[inputKW][search_or_not]=1  #设为搜索过
    client_index[inputKW][2] = 1 # s=="Y"
    return Toekn_S_Addr,Toekn_S_Enc,Token_block,start_file_addr



#server根据收到的token，返回文件结果
def Server_search(Toekn_S_Addr,Toekn_S_Enc,start_file_addr,server_index,list_search_file_ID):
    addr,enc_file=server_index[start_file_addr] #P,V
    ################生成当前G
    # G(t1w,ptr n)
    aes_t1 = AES.new(Toekn_S_Addr, model)  # token做key进行加密
    G_token_S_addr = aes_t1.encrypt(start_file_addr) # G(t_w^1,ptr)
    # G(t2w,ptr n)
    aes_t2 = AES.new(Toekn_S_Enc, model)
    G_token_S_enc = aes_t2.encrypt(start_file_addr) # G(t_w^2,ptr)
    #下一文件地址
    next_file_addr=bytes(a ^ b for a, b in zip(G_token_S_addr, addr)) # P^-1 = G(t_w^1,ptr) \xor P
    #当前文件加密ID
    enc_file_ID=bytes(a ^ b for a, b in zip(G_token_S_enc, enc_file)) # C_f = G(t_w^2,ptr) \xor V
    list_search_file_ID.append(enc_file_ID)
    # print("list_search_file_ID")
    # print(list_search_file_ID)
    # print(enc_file_ID)
    #如果下一文件的地址这个，则停止
    if next_file_addr!=b'NNNNNNNNNNNNNNNN':
        return Server_search(Toekn_S_Addr, Toekn_S_Enc, next_file_addr, server_index, list_search_file_ID)
    else:
        return list_search_file_ID



#添加文件，这里所有文件只有一个关键字
def addfile(addfile_kw, addfile_nonce, addfile_ID,client_index, server_index,blockchain_index,blockchain_addfile_index):
    addr_before = client_index[addfile_kw][3] # 拿到之前保存的地址ptr
    # client生成token（server端文件地址+文件内容）  不变
    # 字符串连接 计算token
    #添加文件blockchain端token更新
    # time=client_index[addfile_kw][1]
    client_index[addfile_kw][1]=client_index[addfile_kw][1]+1 # v = v + 1
    tok_server_addr = (addfile_kw + str(client_index[addfile_kw][0]) + str(1)).zfill(16)  # w||u||1
    tok_server_enc = (addfile_kw + str(client_index[addfile_kw][0]) + str(2)).zfill(16)  # w||u||2
    tok_block = (addfile_kw + str(client_index[addfile_kw][1])).zfill(16) # w||v
    tok_block_last = (addfile_kw + str(client_index[addfile_kw][1]-1)).zfill(16) # w||v-1
    # 转字节
    t_addr = tok_server_addr.encode('utf-8')
    t_enc = tok_server_enc.encode('utf-8')
    t_blo = tok_block.encode('utf-8')
    t_blo_last=tok_block_last.encode('utf-8')
    # 加密生成token
    aes = AES.new(secreat_key, model)
    # 生成token
    Toekn_S_Addr = aes.encrypt(t_addr) # t_w^1 = G(k,w||u||1)
    Toekn_S_Enc = aes.encrypt(t_enc) # t_w^2 = G(k,w||u||2)
    Token_block = aes.encrypt(t_blo) # l_w = G(k,w||v)
    Token_block_last = aes.encrypt(t_blo_last)  # l_w^-1 = G(k,w||v-1)
    #将新加入的文件和nonce添加到server的kw对应索引
    #生成nonce块地址
    str1 = addfile_kw.encode('utf-8') + addfile_nonce  # w||alpha_w
    addr = hmac.new(str1)
    addr_file = addr.digest()  # w_nonce地址 F(w||\alpha_w)
    ################生成当前G
    aes_t1 = AES.new(Toekn_S_Addr, model)  # token做key进行加密
    G_token_S_addr = aes_t1.encrypt(addr_file) # G(t_w^1,nonce)
    # G(t2w,ptr n)
    aes_t2 = AES.new(Toekn_S_Enc, model)
    G_token_S_enc = aes_t2.encrypt(addr_file) # G(w_w^2,nonce)
    #####异或之前文件链的头（即client端的头）
    addr = bytes(a ^ b for a, b in zip(G_token_S_addr, addr_before)) # P_0 = G(t_w^1,nonce) \xor ptr^-1
    #####与nonce值异或
    enc_nonce = bytes(a ^ b for a, b in zip(G_token_S_enc, addfile_nonce ))  # V_0 = G(t_w^2,nonce) \xor ptr^-1
    server_index[addr_file] = [addr, enc_nonce]  # server端nonce块的数据
    # blockchain_index为每个token-所有文件hash的异或
    # hashnonce = hmac.new(addfile_nonce).digest()

    hashnonce=Web3.keccak(addfile_nonce) ##############
    #加文件块

    # 更新client端存储的起始地址
    # addr_before = client_index[addfile_kw][3]
    start_file_addr = (addfile_kw + addfile_ID).encode('utf-8') # w||f^*
    addr = hmac.new(start_file_addr)
    addr_file1 = addr.digest()    #新的起始文件地址 ptr^* = F(w||f^*)
    client_index[addfile_kw][3] = addr_file1 # 更新起始地址
    #####异或下一文件地址，所有nonce块都异或前一个块
    # 上一文件地址
    last_file_addr1 = addr_file # 上一个文件地址是nonce的地址 即 ptr^-1 = F(w||\alpha_w)
    # 异或上一文件地址
    aes_t1 = AES.new(Toekn_S_Addr, model)  # token做key进行加密
    G_token_S_addr1 = aes_t1.encrypt(addr_file1) # G(t_w^1,ptr^*)
    # G(t2w,ptr n)
    aes_t2 = AES.new(Toekn_S_Enc, model)
    G_token_S_enc1 = aes_t2.encrypt(addr_file1) # G(t_w^2,ptr^*)
    addr1 = bytes(a ^ b for a, b in zip(G_token_S_addr1, last_file_addr1)) # P_0 = G(t_w^1,ptr^*) \xor ptr^*
    # 获得文件ID的密文 Enc(k,fi)
    # m = Kw_File_Use[kw][i]
    fileID_en = addfile_ID.encode('utf-8')
    # print(fileID_en)
    enc_file_ID = aes.encrypt(fileID_en) # C_f^* = Enc(k,f^*)

    enc_file1 = bytes(a ^ b for a, b in zip(G_token_S_enc1, enc_file_ID))  # V_0 = G(t_w^2,ptr^*) \xor C_f^*
    server_index[addr_file1] = [addr1, enc_file1]  # server端nonce块的数据

    #blockchain 存储的密文hash
    # enhash = hmac.new(enc_file_ID).digest()
    enhash=Web3.keccak(enc_file_ID) ###################

    # blockchain index 累计异或

    #密文hash
    newhash=bytes(a ^ b for a, b in zip(hashnonce, enhash))
    lastindex=blockchain_index[Token_block_last] # L[l_w^-1]
    blockchain_index[Token_block]=bytes(a ^ b for a, b in zip(newhash,lastindex)) # 更新L中哈希值
    blockchain_addfile_index[Token_block]=bytes(a ^ b for a, b in zip(newhash,lastindex))

    return client_index,server_index,blockchain_index,blockchain_addfile_index



# print(blockchain_index)







#abi


abi_build_index=    """
[
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "bytes16[]",
				"name": "enfile",
				"type": "bytes16[]"
			},
			{
				"internalType": "uint256",
				"name": "len",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "blocknum",
				"type": "uint256"
			}
		],
		"name": "batch_gethash",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"internalType": "bytes16",
				"name": "",
				"type": "bytes16"
			}
		],
		"name": "blockindex",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "blockxor",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "check_",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "check_equal_or_not",
		"outputs": [
			{
				"internalType": "int256",
				"name": "",
				"type": "int256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "current_xor",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "end_xor",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "filehash",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "finish_xor",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "get_computexor",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "uint256",
				"name": "totalnumber",
				"type": "uint256"
			}
		],
		"name": "getlastxor",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"internalType": "bytes16",
				"name": "token",
				"type": "bytes16"
			}
		],
		"name": "gettoken",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "is_equal",
		"outputs": [
			{
				"internalType": "int256",
				"name": "",
				"type": "int256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "recordtoken",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "bytes16",
				"name": "ctoken",
				"type": "bytes16"
			},
			{
				"internalType": "bytes32",
				"name": "dhash",
				"type": "bytes32"
			}
		],
		"name": "set",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "bytes16[]",
				"name": "ctoken",
				"type": "bytes16[]"
			},
			{
				"internalType": "bytes32[]",
				"name": "dhash",
				"type": "bytes32[]"
			},
			{
				"internalType": "uint256",
				"name": "len",
				"type": "uint256"
			}
		],
		"name": "setbatchs",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	}
]
"""

#随机选取一个账户地址
from_account = w3.toChecksumAddress(w3.eth.accounts[0])
abi_build_index = json.loads(abi_build_index)
#合约地址
store_var_contract = w3.eth.contract(
   address=w3.toChecksumAddress('0xEf55f711c49e83fE61401B0e0080f3c2A2fF2d9b'),
   abi=abi_build_index)



# for token in blockchain_index:
#     store_var_contract.functions.set(token,blockchain_index[token]).transact({
#         "from": from_account,
#         "gas": 3000000,
#         "gasPrice": 0,
#     })

# print(len(blockchain_index))

##############################################建立索引


time_start = time.time()  # 记录开始时间
server_index,blockchain_index,client_index=Build_index(Kw_File_Use)
# endb = datetime.datetime.now()
# print("build index time", endb-startb)


#####################将建立的索引分块加到blockchain
batchtoken=[]
batchhash=[]
times=0
batchint=int(len(blockchain_index)/500) # 分几批存入blockchain
batchyue=len(blockchain_index)%500 # 最后一批多少条entry
int_times=0 # 批次
for token in blockchain_index:
    times=times+1 # entry数量
    batchtoken.append(token)
    batchhash.append(blockchain_index[token])
    if times==500 and int_times<batchint:
        int_times=int_times+1
        times=0
        # print(len(batchtoken)) 发布一个交易 sol 的 setbanch函数
        tx_hash11=store_var_contract.functions.setbatchs(batchtoken, batchhash,500).transact({
            "from": from_account,
            "gas": 3000000,
            "gasPrice": 0,
        })
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash11)
        batchtoken=[]
        batchhash=[]
    if int_times==batchint and times==batchyue:
        # print(len(batchtoken))
        tx_hash12=store_var_contract.functions.setbatchs(batchtoken, batchhash, batchyue).transact({
            "from": from_account,
            "gas": 3000000,
            "gasPrice": 0,
        })
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash12)
        print(tx_receipt)

print()
print("----------------运行时间---------------")
print()
time_end = time.time()  # 记录结束时间
time_sum = time_end - time_start  # 计算的时间差为程序的执行时间，单位为秒/s
print(str(time_sum)+' s')


# ##############################################################添加文件
# print("add files!!!!!!!!!!!!!!!!")
# print(client_index)
# start1 = datetime.datetime.now()
# addfilekw=[]
# blockchain_addfile_index={}
# #4000
# add_time=0
# for addfile_kw in client_index:
#     if add_time == 1:
#         break
#     add_time = add_time + 1
#     for i in range(2000):
#         # addfile_kw = kw
#         addfile_nonce = os.urandom(16)  # 生成16位byte
#         addfile_ID = str(np.random.randint(1000000000, 1000000000000)).zfill(16)  # 生成添加文件ID
#         client_index, server_index, blockchain_index, blockchain_addfile_index = addfile(addfile_kw, addfile_nonce,addfile_ID, client_index,server_index, blockchain_index,blockchain_addfile_index)
#     addfilekw.append(addfile_kw)

# end1 = datetime.datetime.now()
# # print("add file time", end1 - start1)
# print("addfile_kw_list",addfilekw)


# print("update time -----------", client_index['john'][1])

# ################################################将更新记录到blockchain
# batchtoken1=[]
# batchhash1=[]
# addtimes=0
# batchint1=int(len(blockchain_addfile_index)/500)
# batchyue1=len(blockchain_addfile_index)%500
# # print(batchint1)
# # print(batchyue1)
# addint_times1=0
# print("blockchain_addfile_index",len(blockchain_addfile_index))

# for token in blockchain_addfile_index:
#     addtimes=addtimes+1
#     batchtoken1.append(token)
#     batchhash1.append(blockchain_addfile_index[token])
#     if addtimes==500 and addint_times1<batchint1:
#         addint_times1=addint_times1+1
#         addtimes=0
#         # print(len(batchtoken1))
#         tx_hash9=store_var_contract.functions.setbatch(batchtoken1, batchhash1,500).transact({
#             "from": from_account,
#             "gas": 3000000,
#             "gasPrice": 0,
#         })
#         tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash9)
#         batchtoken1=[]
#         batchhash1=[]
#     if addint_times1==batchint1 and addtimes==batchyue1:
#         # print(len(batchtoken1))
#         tx_hash10=store_var_contract.functions.setbatch(batchtoken1, batchhash1, batchyue1).transact({
#             "from": from_account,
#             "gas": 3000000,
#             "gasPrice": 0,
#         })
#         tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash10)

# # end1 = datetime.datetime.now()
# # print("add file  time", end1-start1)
# print("blockindex", blockchain_index)

# #打印生成的索引
# # for kw in blockchain_addfile_index:
# #     val = store_var_contract.functions.blockindex(kw).call()
# #     print(val)

# #
# start2 = datetime.datetime.now()
# #########################用户搜索
# timetime=0
# for kw in addfilekw:
#     print(kw)
#     if timetime==1:
#         break
#     timetime=timetime+1

#     Toekn_S_Addr2, Toekn_S_Enc2, Token_block2, start_file_addr2 = user_search_keyword_mutiple(client_index, kw)
#     # server搜索
#     list_search_file_ID1 = []
#     list_search2 = Server_search(Toekn_S_Addr2, Toekn_S_Enc2, start_file_addr2, server_index, list_search_file_ID1)

# Token_block=Token_block2

# end2 = datetime.datetime.now()
# print("search kw", end2-start2)


# # start3 = datetime.datetime.now()
# # i=0
# # for kw in client_index:
# #     i=i+1
# #     if i==35:
# #         break
# #     Toekn_S_Addr1,Toekn_S_Enc1,Token_block1,start_file_addr1=user_search_keyword_mutiple(client_index,kw)
# #     list_search_file_ID1 = []
# #     # start2 = datetime.datetime.now()
# #     list_search = Server_search(Toekn_S_Addr1, Toekn_S_Enc1, start_file_addr1, server_index, list_search_file_ID1)
# #     # end2 = datetime.datetime.now()
# #     # duibitime.append(end2)
# # end3 = datetime.datetime.now()
# # print("duibi实验时间损耗", end3-start3)


# print(len(list_search2))
# print("search list")
# print(list_search2)



# #####################################对搜索结果   list_search2   分块

# # batchtoken1=[]
# # batchhash1=[]
# # addtimes=0
# batchfileint1=int(len(list_search2)/1000)
# batchfileyue1=len(list_search2)%1000
# print("batchfileint1", batchfileint1)
# print("batchfileyue1",batchfileyue1)
# # print(batchint1)
# # print(batchyue1)
# xor_each_result=[]
# earchpart=0
# for i in range(0,len(list_search2),1000):
#     if earchpart<batchfileint1:
#         part=list_search2[i:i+1000]
#         tx_hash5 = store_var_contract.functions.batch_gethash(part, len(part),earchpart).transact({
#             "from": from_account,
#             "gas": 3000000,
#             "gasPrice": 0,
#         })
#         tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash5)
#         # end_hash = store_var_contract.functions.get_computexor().call()
#         # xor_each_result.append(end_hash)
#     else:
#         part=list_search2[i:i+batchfileyue1]
#         print("part",len(part))
#         print(earchpart)
#         tx_hash6 = store_var_contract.functions.batch_gethash(part, len(part),earchpart).transact({
#             "from": from_account,
#             "gas": 3000000,
#             "gasPrice": 0,
#         })
#         tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash6)
#         # end_hash = store_var_contract.functions.get_computexor().call()
#         # xor_each_result.append(end_hash)
#     earchpart = earchpart + 1

# #将所有块的hash拼到一起
# tx_hash7 = store_var_contract.functions.getlastxor(batchfileint1).transact({
#             "from": from_account,
#             "gas": 3000000,
#             "gasPrice": 0,
#         })
# tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash7)


# #
# # # print(xor_each_result)
# # a1=bytes(a ^ b for a, b in zip(xor_each_result[0],xor_each_result[1]))
# # b1=bytes(a ^ b for a, b in zip(a1,xor_each_result[2]))
# # c1=bytes(a ^ b for a, b in zip(b1,xor_each_result[3]))
# # d1=bytes(a ^ b for a, b in zip(c1,xor_each_result[4]))


# # print("d1",d1)
# print("blockchain_index[Token_block]",blockchain_index[Token_block])


# # tx_hash=store_var_contract.functions.batch_gethash(listwait,len(listwait)).transact({
# #             "from": from_account,
# #             "gas": 3000000,
# #             "gasPrice": 0,
# #         })
# #
# # tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)

# # end2 = datetime.datetime.now()
# # print("search time", end2-start2)
# # end_hash=store_var_contract.functions.get_computexor().call()
# # # print("blockchain_index[Token_block]")
# # # print(blockchain_index[Token_block])
# # #

# tx_hash8=store_var_contract.functions.try_whether_equal(Token_block).transact({
#             "from": from_account,
#             "gas": 3000000,
#             "gasPrice": 0,
#         })
# tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash8)


# # tx_hash2=store_var_contract.functions.equal_or_not(blockchain_index[Token_block]).transact({
# #             "from": from_account,
# #             "gas": 3000000,
# #             "gasPrice": 0,
# #         })
# # tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash2)
# # result_verify = store_var_contract.functions.check_equal_or_not().call()

# # aa = store_var_contract.functions.check_().call()
# # print("end xor", aa)

# result_verify = store_var_contract.functions.check_equal_or_not().call()
# time.sleep(10)
# Token_blockhash=store_var_contract.functions.gettoken(b'L\xdd \xa6\x16\xe8[G\xba\xda\xafU\xb22z\x05').call()
# print("Token_blockhash",Token_blockhash)
# print("result_verify")

# # val = store_var_contract.functions.is_equal().call()


# print("val")
# print(result_verify)
# #
# #

