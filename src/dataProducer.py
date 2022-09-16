import numpy as np
import time
import os
from scipy.sparse import csr_matrix
import re
import random
import hmac
import hmac
import random
from Crypto.Cipher import AES
import pickle
import string

#树的深度
d = 3

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


# f_Kw_File_Use = open('InvertedIndex.txt','rb')
# Kw_File_Use=pickle.load(f_Kw_File_Use)
# print(Kw_File_Use)

# updateFileDir = "/home/node2/yangxu/ICC2021/dataset/"
# subs2 = os.listdir(updateFileDir)
# InvertedIndex2 = {}
# for sub in subs2:
#     fileParser(updateFileDir,sub,InvertedIndex2)
# print(InvertedIndex2)
# f_InvertedIndex2 = open("Update_InvertedIndex.txt",'wb') 
# pickle.dump(InvertedIndex2,f_InvertedIndex2,0)
# f_InvertedIndex2.close()