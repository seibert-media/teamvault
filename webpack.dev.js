const {merge} = require('webpack-merge');
const common = require('./webpack.common.js');
const path = require("path");

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
    headers: {
      "Access-Control-Allow-Origin": "*",
    }
  },
});
