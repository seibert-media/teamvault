 const { merge } = require('webpack-merge');
 const common = require('./webpack.common.js');

 module.exports = merge(common, {
   mode: 'production',
   output: {
     publicPath: '/static/bundled/'
   },
   optimization: {
     minimize: true,
     usedExports: true,
   }
 });
