let luaL_loadbufferPtr = Module.findExportByName('libengine.so', 'luaL_loadbuffer');

const hookTest = () => {
	luaL_loadbufferPtr = Module.findExportByName('libengine.so', 'luaL_loadbuffer');
	if (!luaL_loadbufferPtr) {
		console.log('luaL_loadbufferPtr is null');
		setTimeout(hookTest, 1000);
		return;
	} else {
		Interceptor.attach(luaL_loadbufferPtr, {
			onEnter: function(args) {
				let luaState = args[0].toInt32();
				let buff = args[1].readCString();
				let size = args[2].toInt32();
				let name = args[3].readCString();
				// console.log('luaL_loadbuffer: luaState: ' + luaState + ', size: ' + size + ', name: ' + name);
				send({
					'luaState': luaState,
					'savedata': buff,
					'size': size,
					'path': name
				})
			}
		});
	}
}

setTimeout(hookTest, 1000);