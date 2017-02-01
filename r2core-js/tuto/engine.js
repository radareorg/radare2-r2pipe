var level = 0;
/*
const tutorial = [
	{
		"title": "To start we must learn the '?' Command that will show the list of root commands.",
		"expect": {
			"input": "?"
		}
	},{
		"title": "Some commands are used to interact with the user like the echo. Try ?e hello",
		"expect": {
			"output": "hello"
		}
	},{
		"title": "We can get the help and list of subcommands by appending the question mark at the end of any command.",
		"expect": {
			"inputEndsWith": "?"
		}
	}
];
*/

String.prototype.endsWith = String.prototype.endsWith || function(suffix) {
	return this.indexOf(suffix, this.length - suffix.length) >= 0;
};

function checkLevel(inp, out) {
	var e = tutorial[level].expect;
	if (e.input) {
		return inp.trim() == e.input;
	}
	if (e.inputEndsWith) {
		if (inp.trim() !== e.inputEndsWith) {
			return inp.trim().endsWith(e.inputEndsWith);
		}
	}
	if (e.output) {
		return out.trim() == e.output;
	}
	return false;
}

function levelMessage() {
	return tutorial[level].title;
}

function winLevel() {
	level ++;
	if (!tutorial[level]) {
		alert ('The tutorial is over!');
		level = 0;
	} else {
		alert("Good!");
	}
}

function startTutorial() {
	evalTutorial
}
