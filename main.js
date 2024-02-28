/*
** Pseudo Indices and Reserved Indices
** (Lua 5.1)
*/
const LUA_REGISTRYINDEX = -10000;
const LUA_ENVIRONINDEX = -10001;
const LUA_GLOBALSINDEX = -10002;
const LUA_MULTRET = -1;

/*
** Lua error codes
*/

const LUA_OK = 0;
const LUA_ERRRUN = 2;
const LUA_ERRMEM = 4;
const LUA_ERRERR = 5;


/**
 * Lua C API Types
 */

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



let luaStates = [];
let luaStatesPtr = [];


/**
 * Lua C API Functions
 */
let luaL_loadbuffer = null;
let lua_pcall = null;
let lua_type = null;
let luaL_register = null;
let luaL_ref = null;
let luaL_openlibs = null;

let lua_gettop = null;
let lua_getfield = null;
let lua_getglobal = null;
let lua_next = null;
let lua_pop = null;

let lua_settop = null;
let lua_setfield = null;
let lua_setglobal = null;
let lua_pushlstring = null;
let lua_pushstring = null;
let lua_pushcclosure = null;
let lua_pushvalue = null;
let lua_pushglobaltable = null;

let lua_tocfunction = null;
let lua_tostring = null;
let lua_topointer = null;
let lua_tolstring = null;
let lua_tonumber = null;
let lua_toboolean = null;

let lua_iscfunction = null;
let lua_isfunction = null;

let lua_yield = null;
let lua_resume = null;
let lua_status = null;

/**
* Custom Functions
**/ 

const dump_stack = (Lua_state) => {
	let top = lua_gettop(Lua_state);
	console.log('dumping stack: ', top);
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
		send({type: 'dump_stack', index: i, value: value, vType: type});
	}
}

const print_global_table = (Lua_state) => {
	luaL_openlibs(Lua_state);
	lua_pushglobaltable(Lua_state);
	lua_pushnil(Lua_state);
	while (lua_next(Lua_state, -2) != LUA_TNIL) {
		let key = lua_tostring(Lua_state, -2);
		let value = lua_tostring(Lua_state, -1);
		console.log(key + ' = ' + value);
		lua_pop(Lua_state, 1);
	}
	lua_pop(Lua_state, 1);
}

/**
 * Exports and Hooks
 * https://pgl.yoyo.org/luai/i/_  for lua C API functions types and descriptions
 * https://frida.re/docs/javascript-api/ for frida javascript api
 */

const get_lua_exports = () => {
	luaL_loadbuffer = new NativeFunction(Module.findExportByName('libengine.so', 'luaL_loadbuffer'), 'int', ['pointer', 'pointer', 'int', 'pointer']);
	lua_pcall = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pcall'), 'int', ['pointer', 'int', 'int', 'int']);
	lua_type = new NativeFunction(Module.findExportByName('libengine.so', 'lua_type'), 'int', ['pointer', 'int']);
	luaL_register = new NativeFunction(Module.findExportByName('libengine.so', 'luaL_register'), 'void', ['pointer', 'pointer', 'pointer']);
	luaL_openlibs = new NativeFunction(Module.findExportByName('libengine.so', 'luaL_openlibs'), 'void', ['pointer']);
	luaL_ref = new NativeFunction(Module.findExportByName('libengine.so', 'luaL_ref'), 'int', ['pointer', 'int']);
	lua_next = new NativeFunction(Module.findExportByName('libengine.so', 'lua_next'), 'int', ['pointer', 'int']);

	lua_gettop = new NativeFunction(Module.findExportByName('libengine.so', 'lua_gettop'), 'int', ['pointer']);
	lua_getfield = new NativeFunction(Module.findExportByName('libengine.so', 'lua_getfield'), 'void', ['pointer', 'int', 'pointer']);
	
	lua_settop = new NativeFunction(Module.findExportByName('libengine.so', 'lua_settop'), 'void', ['pointer', 'int']);
	lua_setfield = new NativeFunction(Module.findExportByName('libengine.so', 'lua_setfield'), 'void', ['pointer', 'int', 'pointer']);

	lua_pushlstring = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushlstring'), 'void', ['pointer', 'pointer', 'int']);
	lua_pushstring = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushstring'), 'void', ['pointer', 'pointer']);
	lua_pushcclosure = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushcclosure'), 'void', ['pointer', 'pointer', 'int']);
	lua_pushvalue = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushvalue'), 'void', ['pointer', 'int']);
	lua_pushnil = new NativeFunction(Module.findExportByName('libengine.so', 'lua_pushnil'), 'void', ['pointer']);
	
	lua_topointer = new NativeFunction(Module.findExportByName('libengine.so', 'lua_topointer'), 'pointer', ['pointer', 'int']);
	lua_tolstring = new NativeFunction(Module.findExportByName('libengine.so', 'lua_tolstring'), 'pointer', ['pointer', 'int', 'pointer']);
	lua_tocfunction = new NativeFunction(Module.findExportByName('libengine.so', 'lua_tocfunction'), 'pointer', ['pointer', 'int']);
	lua_tonumber = new NativeFunction(Module.findExportByName('libengine.so', 'lua_tonumber'), 'double', ['pointer', 'int']);
	lua_toboolean = new NativeFunction(Module.findExportByName('libengine.so', 'lua_toboolean'), 'int', ['pointer', 'int']);


	lua_yield = new NativeFunction(Module.findExportByName('libengine.so', 'lua_yield'), 'int', ['pointer', 'int']);
	lua_resume = new NativeFunction(Module.findExportByName('libengine.so', 'lua_resume'), 'int', ['pointer', 'int']);
	lua_status = new NativeFunction(Module.findExportByName('libengine.so', 'lua_status'), 'int', ['pointer']);


	lua_iscfunction = new NativeFunction(Module.findExportByName('libengine.so', 'lua_iscfunction'), 'int', ['pointer', 'int']);

	lua_getglobal = (Lua_state, s) => {
		lua_getfield(Lua_state, LUA_GLOBALSINDEX, s);
	}

	lua_setglobal = (Lua_state, s) => {
		lua_setfield(Lua_state, LUA_GLOBALSINDEX, s);
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

	if (!luaL_loadbuffer || !lua_gettop || !lua_settop || !lua_getfield || !lua_pcall || !lua_pushlstring ||
		!lua_pushstring || !lua_pushcclosure || !lua_tocfunction || !lua_topointer || !lua_getglobal || !lua_pop
		|| !lua_tostring || !lua_pushvalue || !lua_tolstring) {
		console.log('error getting lua exports');
		return;
	}

	console.log('got lua exports');
}

// hooks 

/**
 * hook_lua_gettop
 * @description Hook lua_gettop to get the lua states and store them in an array, so we can use them later to execute lua code and interact with the lua states.
 */
const hook_lua_gettop = () => {
	let lua_gettop_ptr = Module.findExportByName('libengine.so', 'lua_gettop');

	if (!lua_gettop_ptr) {
		console.log('lua_gettop_ptr is null');
		setTimeout(hook_lua_gettop, 500);
		return;
	}

	Interceptor.attach(lua_gettop_ptr, {
		onEnter: function(args) {
			let pointer_state = args[0];
			let lua_state = args[0].toInt32();
			if (luaStates.indexOf(lua_state) == -1) {
				luaStates.push(lua_state);
				luaStatesPtr.push(pointer_state);
				console.log('lua_state: ' + lua_state);
			}

			if (luaStates.length > 1) {
				hook_lua_print(luaStatesPtr[1]);
			}
		}
	})

}

/**
 * hook_lua_print
 * @description Hook the print function in lua, so we can intercept the output of the print function calls in lua.
 */

const hook_lua_print = (Lua_state) => {
	let print_string = Memory.allocUtf8String('print');
	lua_pushvalue(Lua_state, LUA_GLOBALSINDEX); // [_G]
	lua_getfield(Lua_state, -1, print_string);  // [_G, print]

	let print_cfunction = lua_tocfunction(Lua_state, -1); // [_G, print]

	Interceptor.attach(print_cfunction, {
		onEnter: function(args) {
			let args_count = lua_gettop(Lua_state);
			let args_str = "";
			for (let i = 1; i <= args_count; i++) {
				let arg = lua_tostring(Lua_state, i);
				args_str += Memory.readUtf8String(arg);
			}
			send({'print': args_str});
		}
	});
	lua_pop(Lua_state, 2); // []
}

/**
 * Execute Lua Code
 */

const execute_lua_code = (code_buffer, size, script_name) => {
	let lua_state = luaStatesPtr[0];
	let buffer = Memory.allocUtf8String(code_buffer);
	let name_ptr = Memory.allocUtf8String(script_name);



	let ret = luaL_loadbuffer(lua_state, buffer, size, name_ptr);

	if (ret == LUA_OK) {
		ret = lua_pcall(lua_state, 0, LUA_MULTRET, 0);
		if (ret != LUA_OK) {
			console.log('lua_pcall error');
		}
	} else {
		console.log('luaL_loadbuffer error');
	}

	console.log("lua_pcall ret: " + ret);

	send({'scriptName': scriptName, 'status': 'success'});
}

/**
 * RPC Exports
 */

rpc.exports = {
	execute_lua(cbuffer, size, scriptname) {
		execute_lua_code(cbuffer, size, scriptname);
	},
	dump_stack() {
		if (luaStatesPtr.length == 0) {
			console.log('no lua states');
			return;
		}
		dump_stack(luaStatesPtr[0]);
	},
	print_global_table() {
		if (luaStatesPtr.length == 0) {
			console.log('no lua states');
			return;
		}
		print_global_table(luaStatesPtr[0]);
	}
}

Java.perform(() => {
	const System = Java.use('java.lang.System');
	const Runtime = Java.use('java.lang.Runtime');
	const SystemLoad = System.loadLibrary.overload('java.lang.String');
	const VMStack = Java.use('dalvik.system.VMStack');

	SystemLoad.implementation = function(library) {
		console.log('Loading dynamic library => ' + library);
		try {
			const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
			if (library.includes('engine')) {
				hook_lua_gettop(); // get em lua states
				setTimeout(() => {
					get_lua_exports();
				}, 500);
			}
			return loaded;
		}
		catch (err) {
			console.log(err);
		};
	}
})