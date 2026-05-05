const { merge } = require('webpack-merge');
const common = require('./rspack.common.js');
const path = require('path');

/** @type {import('@rspack/core').Configuration} */
module.exports = merge(common, {
  mode: 'development',
  devtool: 'eval-cheap-module-source-map',
  // @rspack/cli's `serve` auto-enables lazyCompilation for web targets when
  // unset. Its runtime POSTs to a relative `_rspack/lazy/trigger`, which the
  // browser resolves against the Django origin (localhost:8000), not the
  // rspack dev server (localhost:3000), so dynamic imports never resolve.
  // We could make this work, but it's not worth it.
  lazyCompilation: false,
  output: {
    publicPath: 'http://localhost:3000/dist/',
  },
  devServer: {
    static: path.resolve('./teamvault/static/bundled/'),
    port: 3000,
    devMiddleware: {
      publicPath: '/dist/',
    },
    headers: {
      'Access-Control-Allow-Origin': '*',
    },
    // HMR / live-reload deliberately disabled. The dev server still
    // rebuilds bundles on file change and serves them over HTTP; the
    // browser just needs a manual refresh to pick them up. Keeps the
    // build runnable under Bun, whose node:http upgrade-write path
    // doesn't flush WS handshake bytes (rspack-dev-server's HMR
    // channel relies on that).
    client: false,
    hot: false,
    liveReload: false,
  },
  ignoreWarnings: [
    {
      message: /Deprecation Passing percentage units to the global abs/,
    },
  ],
});
