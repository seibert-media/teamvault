const { merge } = require('webpack-merge');
const common = require('./rspack.common.js');
const path = require('path');

/** @type {import('@rspack/core').Configuration} */
module.exports = merge(common, {
  mode: 'development',
  output: {
    publicPath: 'http://localhost:3000/dist/',
  },
  optimization: {
    minimize: false,
    usedExports: false,
  },
  devServer: {
    static: path.resolve('./teamvault/static/bundled/'),
    hot: true,
    port: 3000,
    devMiddleware: {
      publicPath: '/dist/',
    },
    headers: {
      'Access-Control-Allow-Origin': '*',
    },
  },
  ignoreWarnings: [
    {
      message: /Deprecation Passing percentage units to the global abs/,
    },
  ],
});
