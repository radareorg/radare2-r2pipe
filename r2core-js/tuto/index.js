
var r2 = {};

var cmds = new Array();
var hist = new Array();
var yrotsih = new Array();

function clearCommands() {
	cmds = [];
}

function loadR2Core() {

var xhr = new XMLHttpRequest();
xhr.open('GET', 'r2core.js.gz', true);
//xhr.responseType = 'blob';
xhr.responseType = 'arraybuffer';
xhr.onload = function(e) {
  if (this.status == 200) {
    var myBlob = this.response;
    alert(myBlob);
    var res = pako.inflate(myBlob);
    var
      binaryString = '',
      bytes = new Uint8Array(res),
      length = bytes.length;
    for (var i = 0; i < length; i++) {
      binaryString += String.fromCharCode(bytes[i]);
    }

    var script = document.createElement('script');
    script.innerText = binaryString;
    document.head.appendChild(script);
    setTimeout (ready , 100);
  }
};
xhr.send();
	//var url = URL.createObjectURL(e.target.files[0]);  
	// script.setAttribute('src', url);
}


function runCommand() {
	var input = document.getElementById('input');
	var output = document.getElementById('output');
	var cmd = input.value;
	if (cmd !== '') {
		hist.push(cmd);
	}
	var res = '';
	if (cmd.substring(0, 2) === 'o ') {
		var url = cmd.substring(2);
		if (url.indexOf('http://') !== -1) {
			r2.openurl(0, url);
		} else {
			r2.openurl(0, document.URL + url);
		}
	} else {
		// runCommand();
		res = r2.cmd (0, cmd);
	}

	if (checkLevel(cmd, res)) {
		winLevel();
		var txt = document.getElementById('txt');
		txt.innerHTML = levelMessage();
		speak (txt.innerHTML);
	}
	input.value = '';
	for (var c of cmds) {
		res += "\n[>] " + c + "\n";
		res += r2.cmd (0, c);
	}
	output.innerText = res;
}

function addCommand() {
	var input = document.getElementById('input');
	runCommand();
	cmds.push(input.value);
	input.value = '';
}

function openURL() {
	var url = document.getElementById('url');
	r2.openurl(0, url.value);
}

function histUp() {
	if (hist.length > 0) {
		var input = document.getElementById('input');
		input.value = hist[hist.length - 1];
		yrotsih.push(hist.pop());
	}
}

function histDown() {
	if (yrotsih.length > 0) {
		var input = document.getElementById('input');
		input.value = yrotsih[yrotsih.length - 1];
		hist.push(yrotsih.pop());
	}
}

document.addEventListener('DOMContentLoaded', function () {
	loadR2Core();
});

function ready() {
	r2.cmd = Module.cwrap('r2_asmjs_cmd', 'string', ['number', 'string']);
	r2.openurl = Module.cwrap('r2_asmjs_openurl', 'void', ['number', 'string']);
	r2.cmd(0, "e scr.html=true");
	r2.cmd(0, "e scr.utf8=true");
	r2.cmd(0, "e scr.interactive=false");
	r2.cmd(0, "e scr.color=false");
	var txt = document.getElementById('txt');
	txt.innerHTML = levelMessage();
	speak (txt.innerHTML);
	var add = document.getElementById('add');
	add.addEventListener('click', addCommand);
	var run = document.getElementById('run');
	run.addEventListener('click', runCommand);
	var input = document.getElementById('input');
	input.value = 'o crackme'; // + document.URL + 'crackme';
	input.onkeypress = function(e){
		if (e.keyCode == 13) {
			runCommand();
		} else if (e.keyCode == 38) {
			histUp();
		} else if (e.keyCode == 40) {
			histDown();
		}
        }
/*
	var open = document.getElementById('open');
	open.addEventListener('click', openURL);
	var url = document.getElementById('url');
	url.onkeypress = function(e){
		if (e.keyCode == 13) {
			openURL();
		}
        }
*/
}

// say a message
function speak(text, callback) {
	if (typeof SpeechSynthesisUtterance === 'undefined') {
		return;
	}
	var u = new SpeechSynthesisUtterance();
	u.text = text;
	u.lang = 'en-US';

	u.onend = function() {
		if (callback) {
			callback();
		}
	};

	u.onerror = function(e) {
		if (callback) {
			callback(e);
		}
	};

	speechSynthesis.speak(u);
}
