# Wire

This repository is part of the source code of Wire. You can find more information at [wire.com](https://wire.com) or by contacting opensource@wire.com.

You can find the published source code at [github.com/wireapp](https://github.com/wireapp). 

For licensing information, see the attached LICENSE file and the list of third-party licenses at [wire.com/legal/licenses/](https://wire.com/legal/licenses/).

## Build Status

[![Build Status](https://travis-ci.org/wireapp/proteus.js.svg?branch=master)](https://travis-ci.org/wireapp/proteus.js)

## Usage

```bash
npm install wireapp-proteus
```

```javascript
var Proteus = require('wireapp-proteus');

var ikp = Proteus.keys.IdentityKeyPair.new();
var buffer = ikp.serialise();
var view = new Uint8Array(buffer);

console.log('Identity Key Pair', view);
```

## Run Tests

```bash
npm install
npm test
```