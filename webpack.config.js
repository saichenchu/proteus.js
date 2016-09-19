var webpack = require('webpack');

module.exports = {
  devtool: 'source-map',
  entry: {
    filename: './build/proteus.js'
  },
  output: {
    filename: 'proteus-bundle.min.js',
    library: 'proteus',
    libraryTarget: 'amd',
    path: './dist'
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
    new webpack.optimize.DedupePlugin(),
    new webpack.optimize.UglifyJsPlugin({
      compress: {warnings: false},
      output: {comments: false},
      sourceMap: true
    })
  ]
};
