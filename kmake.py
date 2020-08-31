
import sys
import zlib
import hashlib
import os

def main():
    if len(sys.argv)!=2 :
        print('Usage : kmake.py [file]')
        return

    fname=sys.argv[1]#암호할 파일 입력받음
    tname=fname

    fp=open(tname,'rb')
    buf=fp.read()
    fp.close()
    
    buf2=zlib.compress(buf)#zlib로 암호할 파일을 압축함

    buf3=''
    for c in buf2 :
        buf3+=chr(c^0xFF)#buf2의 값을 1바이트씩 가져와 0xFF랑 ^연산수행 한뒤 buf3에 추가

    buf4='KAVM'+buf3 #buf3(암호화된 내용)앞에 KAVM문자열 추가
    f=buf4
    
    for i in range(3): #md5로 buf4의 해시값을 구한다.
        md5=hashlib.md5()
        md5.update(f.encode())
        f=md5.hexdigest()
    buf4+=f #해시값을 암호화한 내용(buf4)뒤에 추가
    kmd_name=fname.split('.')[0]+'.kmd'#확장자를 .kmd로 변경하고 새로운 파일 생성 
    fp=open(kmd_name,'wb')
    fp.write(buf4.encode())#binary로 encode해줌
    fp.close()

    print('%s -> %s'%(fname,kmd_name))

if __name__=='__main__' :
    main()
