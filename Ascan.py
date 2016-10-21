# -*- coding:utf-8 -*-
#	Python 2.7.11 version
#	2016/10/20	By Qu jingdong
#	ɨ��ip���ж˿ڿ������
#	�÷� python Ascan.py -H 218.107.207.110-218.107.207.120 -P 25,80

import optparse
import socket			#Ҫ��socket.AF_INET,��ΪAF_INET���ֵ��socket�����ƿռ���
from socket import *	#�ǰ�socket�µ������������뵱ǰ���ƿռ�
from threading import *

screenLock = Semaphore(value=100)		#�����ź���

def ip2num(ip):							#��ip��ַתΪlist
    ip=[int(x) for x in ip.split('.')]
    return ip[0] <<24 | ip[1]<<16 | ip[2]<<8 |ip[3]
	
def num2ip(num):						#����listתΪip��ַ
    return '%s.%s.%s.%s' %( (num & 0xff000000) >>24,
                            (num & 0x00ff0000) >>16,
                            (num & 0x0000ff00) >>8,
                            num & 0x000000ff )
							
def getIp(ip):							#���������ip��
    start,end = [ip2num(x) for x in ip.split('-') ]
    return [ num2ip(num) for num in range(start,end+1) if num & 0xff ]

def connScan(ip, tgtPort):
	try:
		connSkt = socket(AF_INET, SOCK_STREAM)
		connSkt.connect((ip,tgtPort))
		screenLock.acquire()		#��ȡ�ź���
		print '[+]%d/tcp open ------%s\n'%(tgtPort,ip)
	except:
		screenLock.acquire()
		return
	finally:
		screenLock.release()
		connSkt.close()
	
def portScan(tgtIps,tgtPorts):
	iplist = getIp(tgtIps)
	if(iplist == None):
		print '[-] illegal ip'
		exit(0)	
	setdefaulttimeout(1)
		
	for ip in iplist:
		for tgtPort in tgtPorts:
			t = Thread(target=connScan, args=(ip, int(tgtPort)))
			t.start()
			
def main():
	parser = optparse.OptionParser("%prog -H <begin Ip>-<end Ip> -P <target port> -T <thread>")	#����һ��ʵ���������÷�
	parser.add_option('-H', dest='tgtIp', type='string', help='specify target host')	#��Ӳ���ѡ�� H(������)
	parser.add_option('-P', dest='tgtPort', type='string', help='specify target port')	#��Ӳ���ѡ�� P(��ɨ��˿�)
	(options, args) = parser.parse_args()	#��ȡѡ��Ͳ���
	tgtIps = options.tgtIp
	tgtPorts = str(options.tgtPort).split(',')
	if(tgtIps == None)|(tgtPorts[0] == None):
		print '[-] You must specify target ip and port[s].'
		exit(0)
	portScan(tgtIps, tgtPorts)
	

	
if __name__=='__main__':
	main()