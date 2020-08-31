import sys
import os
import hashlib
import zlib
import io
import scanmod
import curemod
import imp

VirusDB=[]
vdb=[]
sdb=[]
vsize=[]

def DecodeKMD(fname) :
    try :
        fp=open(fname,'rb')
        buf=fp.read()
        fp.close()
        buf=buf.decode()
        
        buf2=buf[:-32]#암호화된 내용 분리
        fmd5=buf[-32:]#해시값 분리(음수index는 뒤에서부터)

        f=buf2
        for i in range(3):#암호화된 내용의 md5해시python.exe antivirus.py eicar.txt값을 구해서 fmd5와 일치하는지 확인
            md5=hashlib.md5()
            md5.update(f.encode())#다시 encode로 해시값구하기
            f=md5.hexdigest()

        if f!=fmd5 :#일치하지 않으면 내용이 변경된것이므로 error
            raise SystemError

        buf3=b''
        for c in buf2[4:] :#buf2(문자열)의 앞에 4글자는'KAVM'이므로 제외
            x=bytes([ord(c)^0xFF])
            buf3+=x
            
        buf4=zlib.decompress(buf3)#압축을 해제한다.
        buf4=buf4.decode()
        return buf4#복호화된 내용을 return
        
    except :
        pass
    
    return None

def LoadVirusDB():#kmd파일에서 악성코드를 읽어와 복호화한뒤 VirusDB에 추가 
    buf=DecodeKMD('virus.kmd')
    fp=io.StringIO(buf)
    
    while True :
        line=fp.readline()
        if not line : break

        line=line.strip()
        VirusDB.append(line)
    fp.close()
    
def MakeVirusDB():#vdb, vsize 추가
    for pattern in VirusDB:
        t=[]
        v=pattern.split(':')

        scan_func=v[0]
        cure_func=v[1]

        if scan_func=='ScanMD5' :#md5해시이용 
            t.append(v[3])
            t.append(v[4])
            vdb.append(t)

            size=int(v[2])
            if vsize.count(size)==0 :
                vsize.append(size)
        elif scan_func=='ScanStr':#특정위치,문자열사용 
            t.append(int(v[2]))
            t.append(v[3])
            t.append(v[4])
            sdb.append(t)
    
if __name__ =='__main__' :
    LoadVirusDB()
    MakeVirusDB()
    
    if len(sys.argv)!=2 :
        print('Usage : antivirus.py [file]')
        sys.exit(0)
    
    fname=sys.argv[1]#검사 대상 파일

    try:
        m='scanmod'
        f,filename,desc=imp.find_module(m,[''])
        module=imp.load_module(m,f,filename,desc)

        cmd='ret,vname=module.ScanVirus(vdb,vsize,sdb,fname)'
        exec(cmd)
    except ImportError:
        ret,vname=scanmod.ScanVirus(vdb,vsize,sdb,fname)
        
    if ret==True :
        print('%s : %s'%(fname,vname))
        curemod.CureDelete(fname)
    else :
        print('%s : ok'%(fname))
    
