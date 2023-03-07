/*
** Pseudo Indices
*/
const LUA_REGISTRYINDEX = -10000;
const LUA_ENVIRONINDEX = -10001;
const LUA_GLOBALSINDEX = -10002;
const LUA_MULTRET = -1;

/*
** Lua API
*/

let luaStates = [];
let luaStatesPtr = [];


let luaL_loadbuffer = new NativeFunction(Module.findExportByName('libengine.so', 'luaL_loadbuffer'), 'int', ['pointer', 'pointer', 'int', 'pointer']);
let lua_gettop = new NativeFunction(Module.findExportByName('libengine.so', 'lua_gettop'), 'int', ['pointer']);
let lua_settop = new NativeFunction(Module.findExportByName('libengine.so', 'lua_settop'), 'void', ['pointer', 'int']);
let lua_getfield = new NativeFunction(Module.findExportByName('libengine.so', 'lua_getfield'), 'void', ['pointer', 'int', 'pointer']);
let lua_pcall = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pcall'), 'int', ['pointer', 'int', 'int', 'int']);
let lua_pushlstring = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushlstring'), 'void', ['pointer', 'pointer', 'int']);
let lua_pushstring = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushstring'), 'void', ['pointer', 'pointer']);
let lua_pushcclosure = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushcclosure'), 'void', ['pointer', 'pointer', 'int']);
let lua_tocfunction = new NativeFunction(Module.findExportByName('libengine.so', 'lua_tocfunction'), 'pointer', ['pointer', 'int']);

// not exported functions
let lua_getglobal = (Lua_state, s) => {
	lua_getfield(Lua_state, LUA_GLOBALSINDEX, s);
}

let lua_pop = (Lua_state, n) => {
	lua_settop(Lua_state, -(n)- 1);
}


const hookLuaGetTop = () => {
	console.log('hookLuaGetTop');
	let lua_gettopPtr = Module.findExportByName('libengine.so', 'lua_gettop');
	if (!lua_gettopPtr) {
		console.log('lua_gettopPtr is null');
		send({'status': 'lua_gettopPtr is null'})
		setTimeout(hookLuaGetTop, 1000);
		return;
	}
	Interceptor.attach(lua_gettopPtr, {
		onEnter: function(args) {
			let pointerState = args[0];
			let luaState = args[0].toInt32();
			if (luaStates.indexOf(luaState) == -1) {
				luaStates.push(luaState);
				luaStatesPtr.push(pointerState);
				console.log('luaState: ' + luaState);
				send({'luaState': luaState,})
			}
		}
	});
	send({'status': 'hooked lua_gettop'})
}

const hookLuaprint = (Lua_state) => {
	// from global table get print cfunction
	lua_getglobal(Lua_state, "_G"); // [_G]
	lua_getfield(Lua_state, -1, "print"); // [_G, print]
	let printCFunction = lua_tocfunction(Lua_state, -1); // [_G, print]
	lua_pop(Lua_state, 2); // []

	// hook print cfunction
	Interceptor.attach(printCFunction, {
		onEnter: function(args) {
			let str = args[0].readCString();
			console.log('print: ' + str);
		}
	})
	console.log("hooked print")
}


const init = () => {
	send({'status': 'init'})
	hookLuaGetTop();
	luaL_loadbuffer = new NativeFunction(Module.findExportByName('libengine.so', 'luaL_loadbuffer'), 'int', ['pointer', 'pointer', 'int', 'pointer']);
	lua_gettop = new NativeFunction(Module.findExportByName('libengine.so', 'lua_gettop'), 'int', ['pointer']);
	lua_settop = new NativeFunction(Module.findExportByName('libengine.so', 'lua_settop'), 'void', ['pointer', 'int']);
	lua_getfield = new NativeFunction(Module.findExportByName('libengine.so', 'lua_getfield'), 'void', ['pointer', 'int', 'pointer']);
	lua_pcall = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pcall'), 'int', ['pointer', 'int', 'int', 'int']);
	lua_pushlstring = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushlstring'), 'void', ['pointer', 'pointer', 'int']);
	lua_pushstring = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushstring'), 'void', ['pointer', 'pointer']);
	lua_pushcclosure = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushcclosure'), 'void', ['pointer', 'pointer', 'int']);
	lua_tocfunction = new NativeFunction(Module.findExportByName('libengine.so', 'lua_tocfunction'), 'pointer', ['pointer', 'int']);

	rpc.exports = {
		getLuaStates: () => {
			return luaStatesPtr;
		},
		executeLuaCode: (codeBuffer, size) => {
			console.log('executeLuaCode: ' + codeBuffer + ', size: ' + size);

			let luaState = luaStatesPtr[0];
			let buffer = Memory.allocUtf8String(codeBuffer);
			let sizePtr = ptr(size);
			let name = Memory.allocUtf8String('test');

			let ret = luaL_loadbuffer(luaState, buffer, sizePtr, name);

			if (ret == 0) {
				ret = lua_pcall(luaState, 0, LUA_MULTRET, 0);
				if (ret != 0) {
					console.log('lua_pcall error');
				}
			} else {
				console.log('luaL_loadbuffer error');
			}
		},
		hookLuaprintex: () => {
			let luaState = luaStatesPtr[0];
			hookLuaprint(luaState);
		}
	}
}

// init();

setTimeout(init, 2000);
