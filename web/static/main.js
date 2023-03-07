// code mirror 5
CodeMirror.registerHelper("hint", "lua", function(editor, options) {
    const keywords = ["and", "break", "do", "else", "elseif", "end", "false", "for", "function", "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while"];
	const variables = ["_G", "_VERSION", "assert", "collectgarbage", "dofile", "error", "getmetatable", "ipairs", "next", "pairs", "pcall", "print", "rawequal", "rawget", "rawlen", "rawset", "require", "select", "setmetatable", "tonumber", "tostring", "type", "xpcall"]; // Add more globals as necessary
    const tables = ["math", "table"]; // Add more tables as necessary
    const mathFunctions = ["abs", "acos", "asin", "atan", "atan2", "ceil", "cos", "cosh", "deg", "exp", "floor", "fmod", "frexp", "huge", "ldexp", "log", "log10", "max", "min", "modf", "pi", "pow", "rad", "random", "randomseed", "sin", "sinh", "sqrt", "tan", "tanh"];
	const tableFunctions = ["concat", "insert", "pack", "remove", "sort", "unpack"]; // Table library functions

    let cur = editor.getCursor();
    let curLine = editor.getLine(cur.line);
    let curWordStart = cur.ch;
    while (curWordStart && /[\w\d_]/.test(curLine.charAt(curWordStart - 1))) {
        --curWordStart;
    }

    let curWord = curLine.slice(curWordStart, cur.ch);
    let list = [];
    for (let i = 0; i < keywords.length; i++) {
        if (keywords[i].lastIndexOf(curWord, 0) === 0) {
            list.push(keywords[i]);
        }
    }

    for (let i = 0; i < variables.length; i++) {
        if (variables[i].lastIndexOf(curWord, 0) === 0) {
            list.push(variables[i]);
        }
    }

    for (let i = 0; i < tables.length; i++) {
        if (tables[i].lastIndexOf(curWord, 0) === 0) {
            list.push(tables[i]);
        }
    }

    // If the current word matches "math", show the math functions
    if (curWord === "math") {
        for (let i = 0; i < mathFunctions.length; i++) {
            list.push("math." + mathFunctions[i]);
        }
    } else if (curWord === "table") {
		for (let i = 0; i < tableFunctions.length; i++) {
			list.push("table." + tableFunctions[i]);
		}
	}

    return {list: list, from: CodeMirror.Pos(cur.line, curWordStart), to: CodeMirror.Pos(cur.line, cur.ch)};
});

CodeMirror.commands.autocomplete = function(cm) {
	cm.showHint({hint: CodeMirror.hint.lua});
};

let textarea = document.getElementById('code');

let editor = CodeMirror(textarea, {
	value: "local function foo() return 1 end",
	mode:  {name: "lua"},
	lineNumbers: true,
	lineWrapping: true,
	indentUnit: 4,
	indentWithTabs: true,
	theme: "ayu-mirage",
	autofocus: true,
	extraKeys: {"Ctrl-Space": "autocomplete"},
	hintOptions: {hint: CodeMirror.hint.lua, completeSingle: false},
	scrollbarStyle: "overlay",
});

editor.setOption("matchBrackets", true);
editor.setOption("styleActiveLine", true);
editor.setOption("autoCloseBrackets", true);
editor.setOption("autoCloseTags", true);
editor.setOption("highlightSelectionMatches", true);
editor.setOption("showCursorWhenSelecting", true);

editor.setSize("100%", "360px");


const executeBtn = document.getElementById('execute-btn');

executeBtn.addEventListener('click', () => {
	const code = editor.getValue();

	// post request to server
	let jsonData = {
		scriptName: 'test.lua',
		script: code
	}

	fetch('/loadbuffer', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify(jsonData)
	})

});

// console
const consoleOutput = document.querySelector('.console-body');

function logToConsole(message) {
  const newLine = document.createElement('div');
  newLine.innerHTML = `<span class="console-prefix">&gt;</span> ${message}`;
  consoleOutput.appendChild(newLine);
}

function clearConsole() {
    // remove all children
    while (consoleOutput.firstChild) {
        consoleOutput.removeChild(consoleOutput.firstChild);
    }
}

// socketio connection
const socket = io();

socket.on('error', (error) => {
    logToConsole('Error: ' + error);
});

socket.on('status', (status) => {
    let scriptName = status.scriptName;
    let statusMessage = status.statusMessage;
    logToConsole(`[exec]::${scriptName} |STATUS| ${statusMessage}`);
});

socket.on('output', (output) => {
    logToConsole('[print]:' + output);
    console.log(output);
});

socket.on('luaState', (luaState) => {
    logToConsole('[luaState]:' + luaState);
});

socket.on('dumpStack', (dumpStack) => {
    let index = dumpStack.index;
    let value = dumpStack.value;
    let type = dumpStack['vType'];
    logToConsole(`[dumpStack]::${index} |${type}| ${value}`);
});