# create a website where i can use luaL_loadbuffer, to load lua scripts from the web, and then execute them in the game
import frida
import os
from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO

port = 1337
app = Flask(__name__, static_folder='web/static', template_folder='web/template')
socketio = SocketIO(app)
device = None
script = None
isDumping = False


'''
Post request to /loadbuffer with the following json example:
{
	'scriptName': 'sum.lua',
    'script': 'sum = function(a,b) return a+b end'
    'size': -- calculated size of the script
}
'''
@app.route('/loadbuffer', methods=['POST'])
def loadbuffer():
    content = request.json
    scriptName = content['scriptName']
    scriptToLoad = content['script']
    size = len(scriptToLoad.encode('utf-8'))
    print(f"Received script {scriptName} with size {size}")
	# TODO: send script to frida

    if isDumping:
        print('Cannot load script while dumping')
        return jsonify({'status': 'Cannot load script while dumping'})
    if script is None:
        print('Script is None')
        return jsonify({'status': 'Script is None'})
    
    script.exports.execlua(scriptToLoad, size, scriptName);
    return jsonify({'status': 'Sent to frida'})

def savefile(path, data):
    try:
        # add /dumper to the path
        current = os.getcwd() + '/dumper'
        path = os.path.join(current, path)
        if not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))
        with open(path, 'wb') as f:
            f.write(data.encode('utf-8'))
            print(f"Saved data to {path}")
            f.close()
    except Exception as e:
          print(f"Error saving data to {path}: {e}")

def dumpLuaCode(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        path = payload['path']
        if 'savedata' in payload:
            savedata = payload['savedata']
            savefile(path,savedata)
            current = os.getcwd() + '/dumper'
            savedPath = os.path.join(current, path)
            print(f"Saved data to {savedPath}")
            return


@app.route('/dumpCode', methods=['GET'])
def dumpCode():
    global isDumping, script
    device = frida.get_usb_device()
    pid = device.spawn(['com.wan.ddten'])
    session = device.attach(pid)
    with open('luaL_loadbuffer.js') as f:
        sourceDump = f.read()
    script = session.create_script(sourceDump)
    script.on('message', dumpLuaCode)
    script.load()
    device.resume(pid)
    isDumping = True
    return jsonify({'status': 'Dumping code, look at the console'})


def on_message(message, data):
    if message['type'] == 'error':
        print(f"Error: {message['description']}, {message['stack']} {message['fileName']} {message['lineNumber']}")
        socketio.emit('error', message['description'])
        return
    if message['type'] == 'send':
        payload = message['payload']
        print(f"Received message: {payload}")

        if 'print' in payload:
            printStr = payload['print']
            print('emmiting print', printStr)
            socketio.emit('output', printStr, broadcast=True)

        if 'status' in payload:
            scriptName = payload['scriptName']
            status = payload['status']
            socketio.emit('status', {'scriptName': scriptName, 'statusMessage': status})
        
        if payload.get('type') == 'dumpStack':
            index = payload['index']
            value = payload['value']
            vtype = payload['vType']
            print(f"Dumping stack: {index} {value} {vtype}")
            socketio.emit('dumpStack', {'index': index, 'value': value, 'vType': vtype})
        

        if 'luaState' in payload:
            luaState = payload['luaState']
            socketio.emit('luaState', luaState)

@app.route('/loadScript', methods=['GET'])
def loadScript():
    global isDumping, script
    isDumping = False
    try:
        device = frida.get_usb_device()
    except Exception as e:
        print(f"Error getting device: {e}")
        return jsonify({'status': 'Error getting device'})
    
    pid = device.spawn(['com.wan.ddten'])
    session = device.attach(pid)
    with open('luaState.js') as f:
        source = f.read()
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    print('Script loaded')
    return jsonify({'status': 'Script loaded'})


@app.route('/', methods=['GET'])
def scriptEditor():
    return render_template('scriptEditor.html')


@socketio.on('connect')
def test_connect():
    print('Client connected')

if __name__ == '__main__':
    app.run(debug=True)
    socketio.run(app)
