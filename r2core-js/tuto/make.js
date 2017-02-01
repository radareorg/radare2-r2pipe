const YAML = require('yamljs');
console.log('var tutorial = ' + JSON.stringify(YAML.parseFile('tuto01.yaml'), null, '  ') + ';');
