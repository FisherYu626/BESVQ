

def strIsSmaller(abit,bbit):
    sabit = abit
    sbbit = bbit
    if(sabit[0] == '#'):
        sabit = sabit[1:]
    if(sbbit[0] == '#'):
        sbbit = sbbit[1:]

    for i in range(len(sabit)):
        if(sabit[i]<sbbit[i]):
            return True
        if(sabit[i]>sbbit[i]):
            return False
    
    return False

def stradd(abit,num):
    sabit = abit
    if(sabit[0] == '#'):
        sabit = sabit[1:]
    sabit_len = len(sabit)
    a = int(sabit,2)
    x = pow(2,sabit_len)
    a = (a+num)%x
    sabit = bin(a)[2:]
    while(len(sabit)<sabit_len):
        sabit = '0'+sabit
    # print(sabit)
    return '#'+sabit

def GetOBRC(p,d):
    res = []
    a = p[0]
    b = p[1]
    abit = bin(int(a,10))
    bbit = bin(int(b,10))
    abit = abit[2:]
    bbit = bbit[2:]
    while(len(abit)<d):
        abit = '0'+abit
    while(len(bbit)<d):
        bbit = '0'+bbit
    # print(abit)
    # print(bbit)
    abit = '#'+abit
    bbit = '#'+bbit
    while(strIsSmaller(abit,bbit)):
        if(abit[-1] == '1'):
            res.append(abit)
        if(bbit[-1] == '0'):
            res.append(bbit)
        abit = stradd(abit,1)
        bbit = stradd(bbit,-1)
        abit = abit[:-1]
        bbit = bbit[:-1]
    if(abit == bbit):   res.append(abit)
    return res


if __name__ == "__main__":
    p = ['0','4']
    res = GetOBRC(p,4)
    print(len(res))
    for i in res:
        print(i)