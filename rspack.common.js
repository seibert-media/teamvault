const path = require('path');
const BundleTracker = require('webpack-bundle-tracker');

/** @type {import('@rspack/core').Configuration} */
module.exports = {
  context: __dirname,
  target: 'browserslist',
  entry: {
    base: './teamvault/static/js/entries/base.js',
    'secret-detail': './teamvault/static/js/entries/secret-detail.js',
    'secret-addedit': './teamvault/static/js/entries/secret-addedit.js',
  },
  output: {
    path: path.resolve('./teamvault/static/bundled/'),
    filename: '[name]-[contenthash].js',
    chunkFilename: '[name]-[contenthash].js',
    cssFilename: '[name]-[contenthash].css',
    cssChunkFilename: '[name]-[contenthash].css',
  },
  cache: {
    type: 'filesystem',
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
    extensions: ['.js', '.ts'],
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
        test: /\.(eot|ttf|woff|woff2)$/i,
        type: 'asset/resource',
      },
      {
        test: /\.(svg|png|jpg|gif)$/i,
        type: 'asset',
      },
    ],
  },
};
