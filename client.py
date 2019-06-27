import socket 
import sys


class Client():

	def close(self):
		self.send('close_hunter_555')
	
	def send(self, msg):
		try:
			s = socket.socket()
			s.connect(('localhost', 555))
			s.sendall(str(msg).encode())
			msg = s.recv(1048576)
			s.close()
			return msg
		except Exception as e:
			return e



if __name__ == "__main__":
	arg = sys.argv[1]
	client = Client()

	if arg == 'send':
		if not sys.argv[2]:
			print('No message provided')
		else:
			client.send(sys.argv[2])

	elif arg == 'close':
		client.close()
		
	else:
		print("usage: %s send [msg]|close" % sys.argv[0])
		sys.exit(2)
		
	sys.exit(0)


