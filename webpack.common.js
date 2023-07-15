const path = require('path');
const BundleTracker = require('webpack-bundle-tracker');

module.exports = {
  context: __dirname,
  entry: './teamvault/static/js/index.js',
  output: {
    path: path.resolve('./teamvault/static/bundled/'),
    filename: "[name]-[fullhash].js",
    chunkFilename: "[name]-[fullhash].js"
  },
  plugins: [
    new BundleTracker({path: __dirname + '/teamvault', filename: 'webpack-stats.json'}),
  ],
  resolve: {
    extensions: ['*', '.js']
  },
  module: {
    rules: [
      {
        test: /\.(js|jsx)$/i,
        exclude: /node_modules/,
        loader: 'babel-loader',
      },
      {
        test: /\.css$/i,
        use: ['style-loader', 'css-loader'],
      },
      {
        test: /\.s[ac]ss$/i,
        use: ['style-loader', 'css-loader', 'sass-loader'],
      },
      {
        test: /\.(eot|svg|ttf|woff|woff2|png|jpg|gif)$/i,
        type: 'asset',
      },
    ],
  },
}
