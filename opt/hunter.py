#!/usr/bin/python
from __future__ import division
import logging
import json
import socket
import sys
import re, os, platform
from daemon import Daemon
import fnmatch
import stat
import datetime
import mimetypes
import subprocess
import string
import time
import hashlib
import math
import yara
import itertools
import threading
import socket
from multiprocessing import cpu_count, Pool
from multiprocessing.dummy import Pool as ThreadPool
from binaryornot.check import is_binary
#from multiprocessing.dummy import Pool as ThreadPool
from itertools import product

#for debugging
from pprint import pprint


class MyDaemon(Daemon):
	MATCHING_SIGNATURES = []
	YARA_RULES = []
	HASHTABLE = {}
	SIGNATURES_PATH = ''
	signaturesStats = {}
	yara_databases = 0
	hash_count = 0
	results = {}

		# Checks if a file is a valid text file
	def isText(self,filename):
		try:
			
			return not is_binary(filename)
			
		except Exception as e:
			print('isText Eception')
			MyDaemon.logger.error(e)
			

		#Returns a list of files with roots 
	def getFileRoots(self,path):
		file_roots = []
		for root, dirnames, files in os.walk(path):
			for file in files:
				file_roots.append(os.path.join(root,file))
		return file_roots

	def worker(self,file):
		try:
			def mycallback(data):
				try:
					family = data['meta'].get('family')
					if type(family) is str:
						infectedFound(currentfile, family  + "(" + str(data['rule']).replace("_", " ") + ")")
					yara.CALLBACK_CONTINUE
				except Exception as e:
					MyDaemon.logger.error(e)
			def infectedFound(filename, details):
				tmp = []
				if filename in self.results:
					tmp = self.results[filename]
				tmp.append(details)
				self.results[filename] = tmp
			malware = False
			currentfile = file
			fileHandle = open(currentfile, 'rb')
			fileData = fileHandle.read()
			hash = hashlib.md5()
			hash.update(fileData)
			fileHandle.close()
			currentchecksum = hash.hexdigest()
			if currentchecksum in MyDaemon.HASHTABLE:
				malware = str(MyDaemon.HASHTABLE[currentchecksum])
				infectedFound(currentfile, malware)
			if not is_binary(currentfile):
				for rules in MyDaemon.YARA_RULES:
					try:
						result = rules.match(data=fileData, callback=mycallback)
					except:
						pass
			return True
		except Exception as e:
			MyDaemon.logger.error(e)
		
	def FileScan(self,WebPath,key):
		try:
			totalScanned = 0
			totalPermissionsScanned = 0
			currentfile = ''
			
			start_time =  time.time()
			# Thread function

			file_roots = self.getFileRoots(WebPath)
			print('Initiating scan threads')		
			# Threading
			pool = ThreadPool(4)

			print('Done')
			
			status_check = list(pool.map(self.worker, file_roots))

			#for x in file_roots:
			#	self.worker(x)
			pool.close()
			pool.join()
			print(status_check)
			total_time = time.time() - start_time
			print('Scan completed')
			#Handling Response
			ret = {} 
			tjson = ""
			ret["Known viruses"] = MyDaemon.hash_count + MyDaemon.yara_databases
			ret["Engine version"] = 0.1
			ret["infected_urls"] = self.results
			ret["time_elapsed"] = str(total_time)
			return json.dumps(ret)

		except Exception as e:
			MyDaemon.logger.error(e)

	# Load signatures
	def LoadSignatures(self):
		totalDatabases = 0
		loadedDatabases = 0
		for root, dirnames, filenames in os.walk(os.path.join(MyDaemon.SIGNATURES_PATH, "checksum")):
			for filename in fnmatch.filter(filenames, '*.json'):
				try:
					loadedDatabases += 1
					dbdata = open(os.path.join(root, filename))
					signatures = json.loads(dbdata.read())
					dbdata.close()
					for signatureHash in signatures["Database_Hash"]:
						MyDaemon.HASHTABLE[signatureHash["Malware_Hash"]] = signatureHash["Malware_Name"]	

				except:
					pass

		for root, dirnames, filenames in itertools.chain(os.walk(os.path.join(MyDaemon.SIGNATURES_PATH, "more")), os.walk(os.path.join(MyDaemon.SIGNATURES_PATH, "rules"))):
#		for root, dirnames, filenames in os.walk(os.path.join(MyDaemon.SIGNATURES_PATH, "more")):
			for filename in fnmatch.filter(filenames, '*.yar*'):
				totalDatabases += 1
				try:
					loadedDatabases += 1
					filepath = os.path.join(root, filename)
					rules = yara.compile(filepath=filepath)
					MyDaemon.YARA_RULES.append(rules)
					MyDaemon.yara_databases += 1
				except:
					pass
		MyDaemon.hash_count = len(MyDaemon.HASHTABLE)


	#function for getting application path
	def GetApplicationPath(self):
		try:
	   		return os.getcwd()
		except Exception as e:
			print("Error:")
			sys.exit();

	def my_socket(self,port):
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.bind(("", port))
			sock.listen(10000) # become a server socket, maximum 5 connections
			#infinite loop so that function do not terminate and thread do not end.
			while True:
				connection, address = sock.accept()
				data = connection.recv(1048576)
				reply = ""
				if len(data) > 0:
					data = data.decode().split(';')
					if len(data) >= 1:
						reply=self.FileScan(data[1],data[0])
					#print(reply)
					connection.sendall(str(reply).encode())
	  #				  sock.close()
			print('Socket disconnected')
		except Exception as e:
			print('Socket Error')
			MyDaemon.logger.error(e)
		finally:
			sock.close()
	#function starting thread
	def start_up(self):
		#Create two threads as follows
		try:
			#socket thread
			print('Daemon Starting')
			s = threading.Thread(target=self.my_socket, args = (555,))
			s.daemon = True
			s.start()
			print('started server')
			#waiting for thread to finish (infinite)
			print('Daemon Process')
			s.join()
			print('Exited')
		except Exception as e:
			MyDaemon.logger.error(e)
			print("Error: unable to start thread")
	 #function for class init
	def init_me(self):
		try:
			log_path = "./log"
			logging.basicConfig(filename=log_path, level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s %(message)s')
			MyDaemon.logger=logging.getLogger(__name__)
		except Exception as e:
			print("Error: unable to logging")
			sys.exit();
		try:
			MyDaemon.SIGNATURES_PATH = os.path.join(self.GetApplicationPath(), 'signatures')
			if os.path.isdir(MyDaemon.SIGNATURES_PATH):
				self.LoadSignatures()
			else:
				print("Unable to find signatures folder, please check installation.")
				sys.exit()
	
		except Exception as e:
			MyDaemon.logger.error(e)
	#function for start service
	def run(self):
		self.init_me()
		try:
			self.start_up()
		except Exception as e:
			MyDaemon.logger.error(e)

#Execution starts here
if __name__ == "__main__":
	daemon = MyDaemon('/tmp/hunter.py.pid')
	if len(sys.argv) == 2:
		if 'start' == sys.argv[1]:
			print('Starting Hunter')
			daemon.start()
		elif 'stop' == sys.argv[1]:
			daemon.stop()
		elif 'restart' == sys.argv[1]:
			daemon.restart()
		else:
			print("Unknown command")
			sys.exit(2)
			sys.exit(0)
	else:
		print("usage: %s start|stop|restart" % sys.argv[0])
		sys.exit(2)


