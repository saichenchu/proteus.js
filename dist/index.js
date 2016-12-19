var Proteus = require('./commonjs/proteus');

var lastResort = Proteus.keys.PreKey.MAX_PREKEY_ID;
var preKey = Proteus.keys.PreKey.new(lastResort);
var serializedPreKey = preKey.serialise();

console.log(serializedPreKey);
