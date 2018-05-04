var webpack = require('webpack');
var path = require('path');
var SmartBannerPlugin = require('smart-banner-webpack-plugin');
var UnminifiedWebpackPlugin = require('unminified-webpack-plugin');
var telemetry = require('./src/telemetry');
var version = telemetry.version;

var CustomVarLibraryNamePlugin = require('webpack-custom-var-library-name-plugin');

module.exports = {
    devtool: 'source-map',
    entry: {
        'idtoken-verifier': './src/index.js'
    },
    module: {
        loaders: [
            {
                test: /\.js$/,
                loader: 'babel-loader',
                query: {
                    presets: ['es2015']
                }
            }
        ]
    },
    output: {
        path: path.join(__dirname, '../build'),
        filename: '[name].min.js',
        library: 'idtoken-verifier',
        libraryTarget: 'umd',
        umdNamedDefine: true
    },
    resolve: {
        extensions: ['', '.webpack.js', '.web.js', '.js']
    },
    progress: true,
    watchOptions: {
        aggregateTimeout: 500,
        poll: true
    },
    watch: false,
    keepalive: false,
    inline: false,
    stats: {
        colors: true,
        modules: true,
        reasons: true
    },
    plugins: [
        new CustomVarLibraryNamePlugin({
            name: `${telemetry.name}`
        }),
        new webpack.DefinePlugin({
            'process.env': {
                'NODE_ENV': JSON.stringify('production')
            }
        }),
        new webpack.optimize.DedupePlugin(),
        new webpack.optimize.OccurrenceOrderPlugin(),
        new webpack.optimize.AggressiveMergingPlugin(),
        new webpack.optimize.UglifyJsPlugin({
            compress: {warnings: false, screw_ie8: true},
            comments: false
        }),
        new UnminifiedWebpackPlugin(),
        new SmartBannerPlugin(
            `[filename] v${version}\n\nAuthor: Auth0\nDate: ${new Date().toLocaleString()}\nLicense: MIT\n`, // eslint-disable-line
            {raw: false, entryOnly: true}
        )
    ]
};
