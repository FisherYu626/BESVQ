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
import GetOBRC

sys.setrecursionlimit(10000) # 设置递归深度

w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)
print(w3.eth.blockNumber)


#初始设置
lamda = 16
#私钥
Ks=hmac.new(b'chen').digest()
Ke = os.urandom(16)
model = AES.MODE_ECB


def splitBitStr(bitstr):
    subBitStr = []

    for bits in bitstr:
        bit_len = len(bits)
        for i in range(bit_len+1):
            if subBitStr.count('#'+bits[:i]) == 0:
                subBitStr.append('#'+bits[:i])
    
    return subBitStr


def fileParser(dir,fileid,dic):
    wordset = []
    path = dir+fileid
    
    with open(path,"r") as f:
        for line in f.readlines():
            wordset = line.split(",")
    
    bitstr = []
    for word in wordset:
        str = bin(int(word,10))
        str2 = str[2:]
        while(len(str2)<d):
            str2 = '0'+str2
        bitstr.append(str2)
    
    subBitStr = splitBitStr(bitstr)
    print(subBitStr)
    
    for str in subBitStr:
        if dic.get(str):
            dic[str].append(fileid)
        else:
            filelist = []
            filelist.append(fileid)
            dic[str] = filelist


    return

#######################################################建立索引####################################################
def Build_index(Kw_File_Use):

	##################################建server端索引
	server_index={}      #server索引 I
	blockchain_index={}  #发给blockchain的索引 L
	client_index={}  #client索引 S

	
	for i in Kw_File_Use.keys():
		c = 0
		v = 0
		h = 0
		gama = [os.urandom(16)]
		#填充w
		w_string  = i.zfill(16)
		#字符串编码为bytes
		w_bits = w_string.encode('utf-8')
		# print(w_bits)

		#generate Kw
		aes = AES.new(Ks,model)
		Kw = aes.encrypt(w_bits)
		# verify encrypt
		# a_bits = aes.decrypt(Kw)
		# print(a_bits)
		aesKw = AES.new(Kw,model)

		for id in Kw_File_Use[i]:
			#generate gama[c+1]
			gama.append(os.urandom(16))
			addr_c = aesKw.encrypt(gama[c])

			Pc = bytes(a ^ b for a, b in zip(addr_c, gama[c+1]))

			aesKe = AES.new(Ke,model)
			#id||c 先拼接 再置为长度16
			id_str = (id+str(c)).zfill(16)
			id_bytes = id_str.encode('utf-8')
			Vc = aesKe.encrypt(id_bytes)

			server_index[addr_c] = [Pc,Vc]
			Hvc = Web3.keccak(Vc)
			if c==0:
				h = Hvc
			else:
				h = bytes(a ^ b for a, b in zip(h,Hvc))
			c= c+1
		# w||v 先拼接再哈希
		WandV = (i+str(v))
		WandV_bytes = WandV.encode('utf-8')
		Hwv = hmac.new(WandV_bytes)
		lw = Hwv.digest()
		# print(len(lw))
		blockchain_index[lw] = h
		client_index[i]  = [c,v,gama[0],h]

	return server_index,blockchain_index,client_index



#Update Protocol
def Update_index(subkey_id_file,server_index,client_index):


	blockchain_index={}  #发给blockchain的索引 L
	for i in subkey_id_file.keys():
		w_string  = i.zfill(16)
		w_bits = w_string.encode('utf-8')
		aes = AES.new(Ks,model)
		Kw = aes.encrypt(w_bits)
		aesKw = AES.new(Kw,model)
		if i not in client_index.keys():
			c = 0
			v = 0
			h = 0
		else:
			c,v,gama,h = client_index[i]
			v = v+1
			# print(gama)
			# print(h)
		gama_x = os.urandom(16)
		addr_x = aesKw.encrypt(gama_x)
		Px = bytes(a ^ b for a, b in zip(addr_x, gama_x))
		aesKe = AES.new(Ke,model)
		id_str = (subkey_id_file[i]+str(c)).zfill(16)
		id_bytes = id_str.encode('utf-8')
		Vx = aesKe.encrypt(id_bytes)
		
		server_index[addr_x] = [Px,Vx]
		Hvx = Web3.keccak(Vx)
		if c==0:
			hx = Hvx
		else:
			hx = bytes(a ^ b for a, b in zip(h,Hvx))
		c= c+1
		# w||v 先拼接再哈希
		WandV = (i+str(v))
		WandV_bytes = WandV.encode('utf-8')
		Hwv = hmac.new(WandV_bytes)
		lwx = Hwv.digest()
		blockchain_index[lwx] = hx
		client_index[i] = [c,v,gama_x,hx] 

	return blockchain_index	





# # # # # # # # # # # # # # #
# # # #   连接testrpc   # # #  
# # # # # # # # # # # # # # # 
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
print(w3.eth.accounts[0])
abi_build_index = json.loads(abi_build_index)
#合约地址
store_var_contract = w3.eth.contract(
   address=w3.toChecksumAddress('0x27422CF6A2481c4DD8713C683f10d82eEDb7ACef'),
   abi=abi_build_index)

# # # # # # # # # # # # # # #
# # # #   构建索引   # # # # # 
# # # # # # # # # # # # # # # 
#读取kw-file关系
readFileDir = "/home/node2/yangxu/ICC2021/rangeStreaming/"

subs = os.listdir(readFileDir)

InvertedIndex ={}
# print(subs)
for sub in subs:
    fileParser(readFileDir,sub,InvertedIndex)

print(InvertedIndex)
f_InvertedIndex = open('InvertedIndex.txt','wb')
pickle.dump(InvertedIndex, f_InvertedIndex, 0)
f_InvertedIndex.close()

f_Kw_File_Use = open('InvertedIndex.txt','rb')
Kw_File_Use=pickle.load(f_Kw_File_Use)
print(Kw_File_Use)

time_start = time.time()  # 记录开始时间
server_index,blockchain_index,client_index = Build_index(Kw_File_Use)

# print(server_index)
# print(blockchain_index)
print(len(client_index))

#####################将建立的索引分块加到blockchain(批量)
batchtoken=[]
batchhash=[]
times=0
batch = 1 # 每次批处理添加数量
# print(len(blockchain_index))
batchint=int(len(blockchain_index)/batch) # 分几批存入blockchain
batchyue=len(blockchain_index)%batch # 最后一批多少条entry
int_times=0 # 批次
for token in blockchain_index:
	times=times+1 # entry数量
	batchtoken.append(token)
	batchhash.append(blockchain_index[token])
	if times==batch and int_times<batchint:
		int_times=int_times+1
		times=0
		# print(len(batchtoken)) 发布一个交易 sol 的 setbanch函数
		tx_hash11=store_var_contract.functions.setbatchs(batchtoken, batchhash,batch).transact({
			"from": from_account,
			"gas": 3000000,
			"gasPrice": 0,
		})
		tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash11)
		batchtoken=[]
		batchhash=[]
		# print("times: ", int_times,"--- ", tx_receipt)
	if int_times==batchint and times==batchyue:
		# print(len(batchtoken))
		tx_hash12=store_var_contract.functions.setbatchs(batchtoken, batchhash, batchyue).transact({
			"from": from_account,
			"gas": 3000000,
			"gasPrice": 0,
		})
		tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash12) 
		print("times: ", int_times,"--- ", tx_receipt)
# print(w3.eth.blockNumber)

print()
print("----------------加密索引构建时间---------------")
time_end = time.time()  # 记录结束时间
time_sum = time_end - time_start  # 计算的时间差为程序的执行时间，单位为秒/s
print(str(time_sum)+' s')



####################################################################update period
print("addd files!!!!!!!!!!!!!!!!!!!!!!!!!!")
print("now the s includes:")
print(client_index)

# start1 = datetime.datetime.now()

# f_Up_KwFile_Use = open('Update_InvertedIndex.txt','rb')
# Update_Kw_file=pickle.load(f_Up_KwFile_Use)
# print(Update_Kw_file)
updateFileDir = "/home/node2/yangxu/ICC2021/dataset/"
subs2 = os.listdir(updateFileDir)
# Up_blockchain_indexs = []
for sub in subs2:
	Update_Kw_file = {}
	fileParser(updateFileDir,sub,Update_Kw_file)
	print(Update_Kw_file)
	#将dict{key:[]}转为dict{key:value}
	subkey_id_file = {}
	for i in Update_Kw_file:
		for j in Update_Kw_file[i]:
			subkey_id_file[i] = j
	print(subkey_id_file)
	Up_blockchain_index = Update_index(subkey_id_file,server_index,client_index)
	# Up_blockchain_indexs.append(Up_blockchain_index)
	# print(Up_blockchain_indexs)
	#####################将建立的索引分块更新到blockchain(批量)
	batchtoken=[]
	batchhash=[]
	times=0
	batch = 1 # 每次批处理添加数量
	# print(len(Up_blockchain_index))
	batchint=int(len(Up_blockchain_index)/batch) # 分几批存入blockchain
	batchyue=len(Up_blockchain_index)%batch # 最后一批多少条entry
	int_times=0 # 批次
	for token in Up_blockchain_index:
		times=times+1 # entry数量
		batchtoken.append(token)
		batchhash.append(Up_blockchain_index[token])
		if times==batch and int_times<batchint:
			int_times=int_times+1
			times=0
			# print(len(batchtoken)) 发布一个交易 sol 的 setbanch函数
			tx_hash11=store_var_contract.functions.setbatchs(batchtoken, batchhash,batch).transact({
				"from": from_account,
				"gas": 3000000,
				"gasPrice": 0,
			})
			tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash11)
			batchtoken=[]
			batchhash=[]
			# print("times: ", int_times,"--- ", tx_receipt)
		if int_times==batchint and times==batchyue:
			# print(len(batchtoken))
			tx_hash12=store_var_contract.functions.setbatchs(batchtoken, batchhash, batchyue).transact({
				"from": from_account,
				"gas": 3000000,
				"gasPrice": 0,
			})
			tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash12) 
			print("times: ", int_times,"--- ", tx_receipt)


# end1 = datetime.datetime.now()


# print(w3.eth.blockNumber)

# print()
# print("----------------加密索引构建时间---------------")
# time_end = time.time()  # 记录结束时间
# time_sum = time_end - time_start  # 计算的时间差为程序的执行时间，单位为秒/s
# print(str(time_sum)+' s')
