import os
import hashlib

def SearchVDB(vdb,fmd5) :
    for t in vdb:
        if t[0]==fmd5:
            return True, t[1]
    return False, ''

def ScanVirus(vdb,vsize,sdb,fname) :

    ret,vname=ScanMD5(vdb,vsize,fname)#md5해시 이용 

    if ret==True:
        return ret,vname

    fp=open(fname,'rb')#특정위치,특정문자열 이용 
    for t in sdb:
        if ScanStr(fp,t[0],t[1])==True:
            ret=True
            vname=t[2]
            break
    fp.close()
    
    return ret,vname

def ScanMD5(vdb,vsize,fname) :
    ret=False
    vname=''

    size=os.path.getsize(fname)
    if vsize.count(size) :
        fp=open(fname,'rb')
        buf=fp.read()
        fp.close()

        m=hashlib.md5()
        m.update(buf)
        fmd5=m.hexdigest()

        ret,vname=SearchVDB(vdb,fmd5)
        
    return ret,vname

def ScanStr(fp,offset,mal_str) :
    size=len(mal_str)

    fp.seek(offset)
    buf=fp.read(size)
    buf=buf.decode()
    
    if buf==mal_str :
        return True
    else:
        return False


