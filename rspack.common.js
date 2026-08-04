const path = require('path');
const rspack = require('@rspack/core');
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
    // Stoplight Elements is loaded directly by the API docs template
    // (teamvault/templates/api/v2/docs.html), not through an entry point,
    // so copy the prebuilt bundle under stable, unhashed names.
    new rspack.CopyRspackPlugin({
      patterns: [
        {
          from: 'node_modules/@stoplight/elements/web-components.min.js',
          to: 'stoplight-elements.min.js',
        },
        {
          from: 'node_modules/@stoplight/elements/styles.min.css',
          to: 'stoplight-elements.min.css',
        },
      ],
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
