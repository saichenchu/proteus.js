var pkg = require('./package.json');
var webpack = require('webpack');

module.exports = {
  devtool: 'source-map',
  entry: {
    filename: './dist/commonjs/proteus.js'
  },
  output: {
    filename: 'proteus.js',
    library: 'Proteus',
    libraryTarget: 'var',
    path: './dist/window'
  },
  node: {
    fs: 'empty',
    crypto: 'empty'
  },
  externals: {
    'libsodium-native': {
      'request': {}
    }
  },
  plugins: [
    new webpack.BannerPlugin(`${pkg.name} v${pkg.version}`)
  ]
};
