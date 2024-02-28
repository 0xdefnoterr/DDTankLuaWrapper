let luaL_loadbufferPtr = null;

/**
 * luaL_loadbuffer
 * @description The luaL_loadbuffer function loads a buffer as a Lua chunk. This function is used to load lua code. By hooking this function, we can intercept the Lua code that's loaded within the game.
 */
const hook_loadbuffer = () => {
	luaL_loadbufferPtr = Module.findExportByName('libengine.so', 'luaL_loadbuffer');

	if (!luaL_loadbufferPtr) {
		console.log('luaL_loadbufferPtr is null');
		setTimeout(hook_loadbuffer, 100); // retry
		return;
	}

	Interceptor.attach(luaL_loadbufferPtr, {
		onEnter: function(args) {
			let luaState = args[0].toInt32();
			let buff = args[1].readCString();
			let size = args[2].toInt32();
			let name = args[3].readCString();
			send({
				'luaState': luaState,
				'savedata': buff,
				'size': size,
				'path': name
			});
		}
	});
};

setTimeout(hook_loadbuffer, 500);