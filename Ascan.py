# -*- coding:utf-8 -*-
#	Python 2.7.11 version
#	2016/10/20	By Qu jingdong
#	扫描ip段中端口开放情况
#	用法 python Ascan.py -H 218.107.207.110-218.107.207.120 -P 25,80

import optparse
import socket			#要用socket.AF_INET,因为AF_INET这个值在socket的名称空间下
from socket import *	#是把socket下的所有名字引入当前名称空间
from threading import *

screenLock = Semaphore(value=100)		#引入信号量

def ip2num(ip):							#将ip地址转为list
    ip=[int(x) for x in ip.split('.')]
    return ip[0] <<24 | ip[1]<<16 | ip[2]<<8 |ip[3]
	
def num2ip(num):						#将地list转为ip地址
    return '%s.%s.%s.%s' %( (num & 0xff000000) >>24,
                            (num & 0x00ff0000) >>16,
                            (num & 0x0000ff00) >>8,
                            num & 0x000000ff )
							
def getIp(ip):							#解析输入的ip段
    start,end = [ip2num(x) for x in ip.split('-') ]
    return [ num2ip(num) for num in range(start,end+1) if num & 0xff ]

def connScan(ip, tgtPort):
	try:
		connSkt = socket(AF_INET, SOCK_STREAM)
		connSkt.connect((ip,tgtPort))
		screenLock.acquire()		#获取信号量
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
	parser = optparse.OptionParser("%prog -H <begin Ip>-<end Ip> -P <target port> -T <thread>")	#创建一个实例并定义用法
	parser.add_option('-H', dest='tgtIp', type='string', help='specify target host')	#添加参数选项 H(主机段)
	parser.add_option('-P', dest='tgtPort', type='string', help='specify target port')	#添加参数选项 P(待扫描端口)
	(options, args) = parser.parse_args()	#获取选项和参数
	tgtIps = options.tgtIp
	tgtPorts = str(options.tgtPort).split(',')
	if(tgtIps == None)|(tgtPorts[0] == None):
		print '[-] You must specify target ip and port[s].'
		exit(0)
	portScan(tgtIps, tgtPorts)
	

	
if __name__=='__main__':
	main()