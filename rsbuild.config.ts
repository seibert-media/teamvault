import path from 'path';
import {defineConfig} from "@rsbuild/core";
import {pluginSass} from '@rsbuild/plugin-sass';
import BundleTracker from 'webpack-bundle-tracker';

const staticPath = path.join(__dirname, 'teamvault', 'static');

// noinspection JSUnusedGlobalSymbols
export default defineConfig({
    dev: {
        assetPrefix: 'http://localhost:3000/dist/',
        hmr: false,
    },
    server: {
        cors: {origin: '*'},
    },
    plugins: [
        pluginSass(),
    ],
    resolve: {
        extensions: ['*', '.js']
    },
    source: {
        entry: {
            main: path.resolve(staticPath, 'js/index.js'),
        }
    },
    tools: {
        // disable Rsbuild's html plugin since Django renders HTML
        htmlPlugin: false,

        rspack: {
            plugins: [
                new BundleTracker({path: path.resolve(__dirname, 'teamvault'), filename: 'webpack-stats.json'}),
            ],
            module: {
                rules: [
                    {
                        test: /\.ts$/i,
                        exclude: /node_modules/,
                        loader: 'builtin:swc-loader',
                    },
                    {
                        test: /\.css$/i,
                        use: ['builtin:lightningcss-loader'],
                    },
                    {
                        test: /\.(eot|svg|ttf|woff|woff2|png|jpg|gif)$/i,
                        type: 'asset',
                    },
                ],
            },
            output: {
                path: path.resolve(staticPath, 'bundled'),
                filename: "[name]-[fullhash].js",
                chunkFilename: "[name]-[fullhash].js"
            },
            experiments: {
                css: true,  // default in rsbuild/rspack 2.0
            },
        },
    },
})
