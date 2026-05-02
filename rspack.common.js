const path = require('path');
const BundleTracker = require('webpack-bundle-tracker');

/** @type {import('@rspack/core').Configuration} */
module.exports = {
  context: __dirname,
  entry: {
    base: './teamvault/static/js/entries/base.js',
    'secret-detail': './teamvault/static/js/entries/secret-detail.js',
    'secret-addedit': './teamvault/static/js/entries/secret-addedit.js',
  },
  output: {
    path: path.resolve('./teamvault/static/bundled/'),
    filename: '[name]-[fullhash].js',
    chunkFilename: '[name]-[fullhash].js',
    cssFilename: '[name]-[fullhash].css',
    cssChunkFilename: '[name]-[fullhash].css',
  },
  optimization: {
    // All entries share one runtime and module cache. Without this, each entry
    // gets its own instance of shared modules (e.g. Bootstrap), causing issues
    // like duplicate plugin registration and broken event handling.
    runtimeChunk: 'single',
    splitChunks: {
      chunks: 'all',
      cacheGroups: {
        vendor: {
          test: /node_modules/,
          name: 'vendor',
          chunks: 'all',
          minChunks: 2,
        },
      },
    },
  },
  plugins: [
    new BundleTracker({
      path: path.resolve(__dirname, 'teamvault'),
      filename: 'webpack-stats.json',
    }),
  ],
  resolve: {
    extensions: ['*', '.js', '.ts'],
  },
  module: {
    rules: [
      {
        test: /\.(js|jsx|ts|tsx)$/i,
        exclude: /node_modules/,
        loader: 'builtin:swc-loader',
        options: {
          jsc: {
            parser: {
              syntax: 'typescript',
            },
          },
        },
      },
      {
        test: /\.css$/i,
        type: 'css',
      },
      {
        test: /\.s[ac]ss$/i,
        use: [
          {
            loader: 'sass-loader',
            options: {
              sassOptions: {
                api: 'modern-compiler',
                quietDeps: true,
                silenceDeprecations: ['import'],
              },
            },
          },
        ],
        type: 'css',
      },
      {
        test: /\.(eot|svg|ttf|woff|woff2|png|jpg|gif)$/i,
        type: 'asset',
      },
    ],
  },
};
