// let lua_gettopPtr = Module.findExportByName('libengine.so', 'lua_gettop');
let luaStatesPtr = [];
// pseudo indices
const LUA_REGISTRYINDEX = -10000;
const LUA_ENVIRONINDEX = -10001;
const LUA_GLOBALSINDEX = -10002;
const LUA_MULTRET = -1;

// thread status 0 is ok
const LUA_OK = 0;
const LUA_YIELD = 1;
const LUA_ERRRUN = 2;
const LUA_ERRSYNTAX = 3;
const LUA_ERRMEM = 4;
const LUA_ERRERR = 5;

// lua basic types
const LUA_TNONE = -1;
const LUA_TNIL = 0;
const LUA_TBOOLEAN = 1;
const LUA_TLIGHTUSERDATA = 2;
const LUA_TNUMBER = 3;
const LUA_TSTRING = 4;
const LUA_TTABLE = 5;
const LUA_TFUNCTION = 6;
const LUA_TUSERDATA = 7;
const LUA_TTHREAD = 8;

let hopeLoaded = false;


//specific functions 
let luaL_loadbuffer = undefined;
let lua_pcall = undefined;
let lua_type = undefined;

// stack manipulation
// get functions
let lua_gettop = undefined;
let lua_getfield = undefined;
let lua_getglobal = undefined;


// set & push functions
let lua_settop = undefined;
let lua_pushlstring = undefined;
let lua_pushstring = undefined;
let lua_pushcclosure = undefined;
let lua_pushvalue = undefined;
let lua_pushglobaltable = undefined;
// to functions
let lua_tocfunction = undefined;
let lua_tostring = undefined;
let lua_topointer = undefined
let lua_tolstring = undefined;
let lua_tonumber = undefined;
let lua_toboolean = undefined;
// compare functions
let lua_iscfunction = undefined;
let lua_isfunction = undefined;
//pop
let lua_pop = undefined;

// coroutine functions
let lua_yield = undefined;
let lua_resume = undefined;
let lua_status = undefined;


// not exported functions


// dump lua stack for debug
const dumpStack = (Lua_state) => {
	let top = lua_gettop(Lua_state);
	console.log('dumpStack: ', top);
	for (let i = 1; i <= top; i++) {
		let type = lua_type(Lua_state, i);
		let value = "";
		switch (type) 
		{
			case LUA_TNONE:
				type = 'LUA_TNONE';
				value = 'undefined';
				break;
			case LUA_TNIL:
				type = 'LUA_TNIL';
				value = 'nil';
				break;
			case LUA_TBOOLEAN:
				type = 'LUA_TBOOLEAN';
				value = lua_toboolean(Lua_state, i) ? 'true' : 'false';
				break;
			case LUA_TLIGHTUSERDATA:
				type = 'LUA_TLIGHTUSERDATA';
				break;
			case LUA_TNUMBER:
				type = 'LUA_TNUMBER';
				value = lua_tonumber(Lua_state, i);
				break;
			case LUA_TSTRING:
				type = 'LUA_TSTRING';
				value = lua_tostring(Lua_state, i);
				break;
			case LUA_TTABLE:
				type = 'LUA_TTABLE';
				// get table name
				value = lua_topointer(Lua_state, i);
				break;
			case LUA_TFUNCTION:
				type = 'LUA_TFUNCTION';
				// get function name
				value = lua_topointer(Lua_state, i);
				break;
			case LUA_TUSERDATA:
				type = 'LUA_TUSERDATA';
				break;
			case LUA_TTHREAD:
				type = 'LUA_TTHREAD';
				break;
			default:
				type = 'unknown';
				break;
		}
		send({type: 'dumpStack', index: i, value: value, vType: type});
	}
}


const hookLuaprint = (Lua_state) => {
	// hook print
	if (!lua_pushvalue || !lua_getfield || !lua_tocfunction || !lua_pop || !lua_tostring) {
		console.log('hook print failed');
		return;
	}


	// let print = Memory.allocUtf8String('print');


	let print = Memory.allocUtf8String('print');


	// lua_pushglobaltable(Lua_state); // [_G]
	// lua_getfield(Lua_state, -1, print); // [_G, print]

	// let originalPrint = lua_tocfunction(Lua_state, -1);
	// console.log('originalPrint: ', originalPrint);

	// dumpStack(Lua_state);

	// lua_pop(Lua_state, 2); // []


	// lua_getglobal(Lua_state, print); // [print]


	// let originalPrint = lua_tocfunction(Lua_state, -1);

	// console.log('originalPrint: ', originalPrint);

	// dumpStack(Lua_state);

	// lua_pop(Lua_state, 1); // []


	// lua_pushvalue(Lua_state, LUA_GLOBALSINDEX); // [_G]
	// lua_getfield(Lua_state, -1, print); // [_G, print]

	// if (lua_isfunction(Lua_state, -1)) {
	// 	console.log('print is function');
	// } else {
	// 	console.log('print is not cfunction');
	// }

	// let originalPrint = lua_tocfunction(Lua_state, -1);
	// console.log('originalPrint: ', originalPrint);

	
	
	// lua_pop(Lua_state, 2); // []
	
	
	
	lua_pushvalue(Lua_state, LUA_GLOBALSINDEX); // [_G]
	lua_getfield(Lua_state, -1, print); // [_G, print]
	// get print cfunction
	let originalPrint = lua_tocfunction(Lua_state, -2);
	dumpStack(Lua_state);
	
	lua_pop(Lua_state, 2); // []
	// lua_pop(Lua_state, 1); // []
	

	Interceptor.attach(originalPrint, {
		onEnter: function(args) {
			console.log('hook print');
		}
	});
	

	// get print cfunction

	// hook print
	// Interceptor.attach(originalPrint, {
	// 	onEnter: function(args) {
	// 		print('hook print');
	// 		let argsLength = lua_gettop(Lua_state);
	// 		let argsString = '';
	// 		for (let i = 1; i <= argsLength; i++) {
	// 			let arg = lua_tostring(Lua_state, i);
	// 			argsString += Memory.readUtf8String(arg);	
	// 		}

	// 		send({'print': argsString})
	// 		console.log('print: ' + argsString);
	// 	}
	// });

	console.log('hook print success');
}



let luaState = 0;
let luaStateArray = [];

// hook lua_gettop and save the luaState

const getExports = () => {
	console.log('getExports');
	// get native functions
	luaL_loadbuffer = new NativeFunction(Module.findExportByName('libengine.so', 'luaL_loadbuffer'), 'int', ['pointer', 'pointer', 'int', 'pointer']);
	lua_pcall = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pcall'), 'int', ['pointer', 'int', 'int', 'int']);
	lua_type = new NativeFunction(Module.findExportByName('libengine.so', 'lua_type'), 'int', ['pointer', 'int']);
	
	lua_gettop = new NativeFunction(Module.findExportByName('libengine.so', 'lua_gettop'), 'int', ['pointer']);
	lua_getfield = new NativeFunction(Module.findExportByName('libengine.so', 'lua_getfield'), 'void', ['pointer', 'int', 'pointer']);
	
	lua_settop = new NativeFunction(Module.findExportByName('libengine.so', 'lua_settop'), 'void', ['pointer', 'int']);
	
	lua_pushlstring = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushlstring'), 'void', ['pointer', 'pointer', 'int']);
	lua_pushstring = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushstring'), 'void', ['pointer', 'pointer']);
	lua_pushcclosure = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushcclosure'), 'void', ['pointer', 'pointer', 'int']);
	lua_pushvalue = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushvalue'), 'void', ['pointer', 'int']);
	
	lua_topointer = new NativeFunction(Module.findExportByName('libengine.so', 'lua_topointer'), 'pointer', ['pointer', 'int']);
	lua_tolstring = new NativeFunction(Module.findExportByName('libengine.so', 'lua_tolstring'), 'pointer', ['pointer', 'int', 'pointer']);
	lua_tocfunction = new NativeFunction(Module.findExportByName('libengine.so', 'lua_tocfunction'), 'pointer', ['pointer', 'int']);
	lua_tonumber = new NativeFunction(Module.findExportByName('libengine.so', 'lua_tonumber'), 'double', ['pointer', 'int']);
	lua_toboolean = new NativeFunction(Module.findExportByName('libengine.so', 'lua_toboolean'), 'int', ['pointer', 'int']);
	// coroutine functions
	lua_yield = new NativeFunction(Module.findExportByName('libengine.so', 'lua_yield'), 'int', ['pointer', 'int']);
	lua_resume = new NativeFunction(Module.findExportByName('libengine.so', 'lua_resume'), 'int', ['pointer', 'int']);
	lua_status = new NativeFunction(Module.findExportByName('libengine.so', 'lua_status'), 'int', ['pointer']);


	lua_iscfunction = new NativeFunction(Module.findExportByName('libengine.so', 'lua_iscfunction'), 'int', ['pointer', 'int']);


	lua_getglobal = (Lua_state, s) => {
		lua_getfield(Lua_state, LUA_GLOBALSINDEX, (s));
	}

	lua_pop = (Lua_state, n) => {
		lua_settop(Lua_state, -(n)- 1);
	}

	lua_tostring = (Lua_state, i) => {
		return lua_tolstring(Lua_state, (i), NULL);
	}
	lua_isfunction = (Lua_state, n) => {
		return (lua_type(Lua_state, (n)) == LUA_TFUNCTION);
	}

	lua_pushglobaltable = (Lua_state) => {
		lua_pushvalue(Lua_state, LUA_GLOBALSINDEX);
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
}

const hookLuaGetTop = async () => {
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

				// hook print

				// setTimeout(hookLuaprint(luaStatesPtr[), 1000);

				// if (luaStatesPtr.length == 2) {
					// hook print
					// setTimeout(hookLuaprint(luaStatesPtr[0]), 22000);
					// hook print
					// hookLuaprint(luaStatesPtr[0]);
				// }
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

	if (ret != LUA_OK) {
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
			if (library.includes('engine') && !hopeLoaded)
			{

				setTimeout(() => {
					getExports();
					hookLuaGetTop()
					setTimeout(() => {
						hookLuaprint(luaStatesPtr[0]);
					}, 2000);
				}, 2000);
				
				hopeLoaded = true;
			}
            return loaded;
        } catch(ex) {
            console.log(ex);
        }
    };


});