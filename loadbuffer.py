import time
import frida
import os
import sys


def savefile(path,data):
	try:
		if not os.path.exists(os.path.dirname(path)):
			os.makedirs(os.path.dirname(path))
		with open(path, 'wb') as f:
			f.write(data.encode('utf-8'))
			print(f"Saved data to {path}")
			f.close()
	except Exception as e:
		print(f"Error saving data to {path}: {e}")

def on_message(message, data):
	if message['type'] == 'send':
		payload = message['payload']
		path = payload['path']
		if 'savedata' in payload:
			savedata = payload['savedata']
			savefile(path,savedata)
			return
		savefile(path, data)


def main():
	device = frida.get_usb_device()
	pid = device.spawn(['com.wan.ddten'])
	session = device.attach(pid)
	with open('luaL_loadbuffer.js') as f:
		source = f.read()
	script = session.create_script(source)
	script.on('message', on_message)
	script.load()
	device.resume(pid)
	time.sleep(3)
	sys.stdin.read()

if __name__ == '__main__':
	main()