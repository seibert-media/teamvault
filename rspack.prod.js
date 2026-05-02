const { merge } = require('webpack-merge');
const common = require('./rspack.common.js');

/** @type {import('@rspack/core').Configuration} */
module.exports = merge(common, {
  mode: 'production',
  devtool: 'source-map',
  output: {
    publicPath: '/static/bundled/',
  },
  optimization: {
    minimize: true,
    usedExports: true,
  },
});
