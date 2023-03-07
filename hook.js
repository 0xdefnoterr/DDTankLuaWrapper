// let lua_gettopPtr = Module.findExportByName('libengine.so', 'lua_gettop');
let luaStatesPtr = [];

const LUA_REGISTRYINDEX = -10000;
const LUA_ENVIRONINDEX = -10001;
const LUA_GLOBALSINDEX = -10002;
const LUA_MULTRET = -1;


let luaL_loadbuffer = undefined;
let lua_gettop = undefined;
let lua_settop = undefined;
let lua_getfield = undefined;
let lua_pcall = undefined;
let lua_pushlstring = undefined;
let lua_pushstring = undefined;
let lua_pushcclosure = undefined;
let lua_tocfunction = undefined;
let lua_topointer = undefined
let lua_pushvalue = undefined;
let lua_tolstring = undefined;

// not exported functions
let lua_getglobal = undefined;
let lua_pop = undefined;
let lua_tostring = undefined;


const hookLuaprint = (Lua_state) => {
	// hook print
	let print = Memory.allocUtf8String('print');
	lua_pushvalue(Lua_state, LUA_GLOBALSINDEX); // [_G]
	lua_getfield(Lua_state, -1, print); // [_G, print]
	// get print cfunction
	let originalPrint = lua_tocfunction(Lua_state, -1);
	console.log('originalPrint: ' + originalPrint);
	// hook print
	Interceptor.attach(originalPrint, {
		onEnter: function(args) {
			let argsLength = lua_gettop(Lua_state);
			let argsString = '';
			for (let i = 1; i <= argsLength; i++) {
				let arg = lua_tostring(Lua_state, i);
				argsString += Memory.readUtf8String(arg);	
			}

			send({'print': argsString})
			// console.log('print: ' + argsString);
		}
	});

	lua_pop(Lua_state, 2); // []
}



let luaState = 0;
let luaStateArray = [];

// hook lua_gettop and save the luaState

const getExports = () => {
	console.log('getExports');
	// get native functions
	luaL_loadbuffer = new NativeFunction(Module.findExportByName('libengine.so', 'luaL_loadbuffer'), 'int', ['pointer', 'pointer', 'int', 'pointer']);
	lua_gettop = new NativeFunction(Module.findExportByName('libengine.so', 'lua_gettop'), 'int', ['pointer']);
	lua_settop = new NativeFunction(Module.findExportByName('libengine.so', 'lua_settop'), 'void', ['pointer', 'int']);
	lua_getfield = new NativeFunction(Module.findExportByName('libengine.so', 'lua_getfield'), 'void', ['pointer', 'int', 'pointer']);
	lua_pcall = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pcall'), 'int', ['pointer', 'int', 'int', 'int']);
	lua_pushlstring = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushlstring'), 'void', ['pointer', 'pointer', 'int']);
	lua_pushstring = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushstring'), 'void', ['pointer', 'pointer']);
	lua_pushcclosure = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushcclosure'), 'void', ['pointer', 'pointer', 'int']);
	lua_tocfunction = new NativeFunction(Module.findExportByName('libengine.so', 'lua_tocfunction'), 'pointer', ['pointer', 'int']);
	lua_topointer = new NativeFunction(Module.findExportByName('libengine.so', 'lua_topointer'), 'pointer', ['pointer', 'int']);
	lua_pushvalue = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushvalue'), 'void', ['pointer', 'int']);
	lua_tolstring = new NativeFunction(Module.findExportByName('libengine.so', 'lua_tolstring'), 'pointer', ['pointer', 'int', 'pointer']);


	lua_getglobal = (Lua_state, s) => {
		lua_getfield(Lua_state, LUA_GLOBALSINDEX, (s));
	}

	lua_pop = (Lua_state, n) => {
		lua_settop(Lua_state, -(n)- 1);
	}

	lua_tostring = (Lua_state, i) => {
		return lua_tolstring(Lua_state, (i), NULL);
	}
	
	// if not found, try again
	if (!luaL_loadbuffer || !lua_gettop || !lua_settop || !lua_getfield || !lua_pcall || !lua_pushlstring ||
		 !lua_pushstring || !lua_pushcclosure || !lua_tocfunction || !lua_topointer || !lua_getglobal || !lua_pop
		 || !lua_tostring || !lua_pushvalue || !lua_tolstring) {
		console.log('getExports failed');
		setTimeout(getExports, 1000);
		return;
	}
	console.log('getExports success');

	// hookprint
	if (luaStatesPtr.length > 1) {
		console.log('hooking print');
		hookLuaprint(luaStatesPtr[1]);
	} else {
		console.log('luaStatesPtr is empty');
		setTimeout(getExports, 1000);
	}

}

const hookLuaGetTop = () => {
	let lua_gettopPtr = Module.findExportByName('libengine.so', 'lua_gettop');
	if (!lua_gettopPtr) {
		console.log('lua_gettopPtr is null');
		setTimeout(hookLuaGetTop, 1000);
		return;
	}

	Interceptor.attach(lua_gettopPtr, {
		onEnter: function(args) {
			luaState = args[0].toInt32();
			if (luaStateArray.indexOf(luaState) == -1) {
				luaStateArray.push(luaState);
				luaStatesPtr.push(args[0]);
				send({'luaState': args[0]});
			}

			// if (oldLuaState != luaState) {
				// console.log('luaState: ' + luaState);
				// oldLuaState = luaState;
			// }
		}
	});
	console.log('hook lua_gettop success');
}

// hook print function


const executeLuaCode = (codeBuffer, size, scriptName) => {
	// we have luaState, now we can use luaL_loadbuffer to execute the buffer
	console.log('executing: ' + scriptName);

	let luaStatePtr = luaStatesPtr[0];
	let bufferPtr = Memory.allocUtf8String(codeBuffer);
	let namePtr = Memory.allocUtf8String(scriptName);

	console.log('state and buffer allocated');

	let ret = luaL_loadbuffer(luaStatePtr, bufferPtr, size, namePtr);

	console.log('luaL_loadbuffer called');

	if (ret != 0) {
		console.log('luaL_loadbufferFunc failed');
		send({'scriptName': scriptName, 'status': 'failed at luaL_loadbuffer'})
		return;
	}

	console.log('luaL_loadbuffer success');

	// call

	

	// ret = lua_pcall(luaStatePtr, 0, 0, 0);


	// if (ret != 0) {
	// 	console.log('lua_pcallFunc failed');
	// 	send({'scriptName': scriptName, 'status': 'failed at lua_pcall'})
	// 	return;
	// }

	console.log('Sucessfully executed: ' + scriptName);
	send({'scriptName': scriptName, 'status': 'success'})
}


function receiveExec(json) {
  let codeToExecute = json['payload']['buffer'];
  let size = json['payload']['size'];
  let name = json['payload']['name'];
  console.log(name, size);
  executeLuaCode(codeToExecute, size, name);
}



rpc.exports = {
	execlua(codeBuffer, size, scriptName) {
		executeLuaCode(codeBuffer, size, scriptName);
		return true;
	}
}
// }

// // hook lua_gettop and save the luaState
// setTimeout(hookLuaGetTop, 5000);
// // get exports
// setTimeout(getExports, 10000);

Java.perform(function() {
    const System = Java.use('java.lang.System');
    const Runtime = Java.use('java.lang.Runtime');
    const SystemLoad_2 = System.loadLibrary.overload('java.lang.String');
    const VMStack = Java.use('dalvik.system.VMStack');

    SystemLoad_2.implementation = function(library) {
        console.log("Loading dynamic library => " + library);
        try {
            const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
            if(library.includes("engine")) {
                // do stuff
				hookLuaGetTop();
				setTimeout(getExports, 1000);
            }
            return loaded;
        } catch(ex) {
            console.log(ex);
        }
    };
});