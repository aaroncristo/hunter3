#!/usr/bin/python
#from __future__ import division
import logging
import json
import socket
import sys
import re, os
from daemon import Daemon
import fnmatch
import time
import hashlib
import yara
import itertools
import threading
from multiprocessing import cpu_count, Process
from multiprocessing.dummy import Pool as ThreadPool
from binaryornot.check import is_binary
#from itertools import product
from client import Client


class MyDaemon(Daemon):
	YARA_RULES = []
	HASHTABLE = {}
	SIGNATURES_PATH = ''
	yara_databases = 0
	hash_count = 0
	results = {}

	#Returns a list of files with roots 
	def getFileRoots(self,path):
            file_roots = []
            for root, dirnames, files in os.walk(path):
                for file in files:
                    file_roots.append(os.path.join(root,file))
            return file_roots

	def worker(self,file):
		try:
			print('test print', file)
			def mycallback(data):
				try:
					family = data['meta'].get('family')
					if type(family) is str:
						infectedFound(currentfile, family  + "(" + str(data['rule']).replace("_", " ") + ")")
	#					infectedFound(currentfile, data);
#						score = data['meta'].get('score');
#						print('score:::', score);
#						if type(score) is int:
						#	infectedFound(currentfile, family  + "(" + str(data['rule']).replace("_", " ") + ")", score)
					yara.CALLBACK_CONTINUE
				except Exception as e:
					MyDaemon.logger.error(e)
			def infectedFound(filename, details):
				print('infectedFound', details);
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
			print('currentCheckSUm', currentchecksum)
			if currentchecksum in MyDaemon.HASHTABLE:
				print('inside worker if checksum,,', currentchecksum)
				malware = str(MyDaemon.HASHTABLE[currentchecksum])
				infectedFound(currentfile, malware)
			if not is_binary(currentfile):
				for rules in MyDaemon.YARA_RULES:
					try:
						print('inside worker not is_binary:  fileData to callback');
						print(rules)
						result = rules.match(data=fileData, callback=mycallback,  which_callbacks=yara.CALLBACK_MATCHES)
                                                
					except:
						pass
			return True
		except Exception as e:
			MyDaemon.logger.error(e)
			return False
		
	def FileScan(self,WebPath,key):
		try:
			self.results = {}
			start_time =  time.time()

			file_roots = self.getFileRoots(WebPath)
			print('Initiating scan threads')		
			# Threading
			pool = ThreadPool(cpu_count() * 1)

			print('Done')
			print('file_tool', file_roots)
			status_check = list(pool.map(self.worker, file_roots))

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
			print('scan completed..');

		except Exception as e:
			MyDaemon.logger.error(e)

	# Load signatures
	def LoadSignatures(self):
		print('loadSignatures');
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
	def childSocketProcess(self, connect, data):
		try:
			reply=self.FileScan(data[1],data[0])
			connect.sendall(str(reply).encode())
		except Exception as e:
			MyDaemon.logger.error(e)
			
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
				data = data.decode()
				if len(data) > 0:
					if data == "close_hunter_555":
						connection.sendall(str('Terminating Server').encode())
						break
					
					data = data.split(';')
					if len(data) >= 1:
						w_process = Process(target=self.childSocketProcess, args=( connection, data,))
						w_process.daemon = True
						w_process.start()
#						reply=self.FileScan(data[1],data[0])
					#print(reply)
#					connection.sendall(str(reply).encode())
	  #				  sock.close()
			sock.close()
			print('Socket disconnected')
		except Exception as e:
			print('Socket Error')
			MyDaemon.logger.error(e)
			
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
			return False
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
		print('init me');
		self.init_me()
		try:
			for tries in range(0,20):
				if self.start_up() is False:
					print('Retrying..', tries+1)
					time.sleep(5)
				else:
					running = True
					break
			if running is not True:
				MyDaemon.logger.error("Failed to start daemon")
		except Exception as e:
			MyDaemon.logger.error(e)

#Execution starts here
if __name__ == "__main__":
	daemon = MyDaemon('/tmp/hunter.py.pid')
	client = Client()
	if len(sys.argv) == 2:
		if 'start' == sys.argv[1]:
			print('Starting Hunter')
			daemon.start()
		elif 'stop' == sys.argv[1]:
			client.close()
			daemon.stop()
		elif 'restart' == sys.argv[1]:
			client.close()
			daemon.restart()
		else:
			print("Unknown command")
			sys.exit(2)
	else:
		print("usage: %s start|stop|restart" % sys.argv[0])
		sys.exit(2)
