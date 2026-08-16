// webpack-ext-reloader is a maintained fork of webpack-extension-reloader
// that supports webpack 5 (the original only supports webpack 4).

const path = require('path');
const { merge } = require('webpack-merge');
const dev = require('./webpack.dev.js');
const ExtensionReloader = require('webpack-ext-reloader');
const {exec} = require('child_process');

// after compiling, the tests will automatically be run each time a file change occurs
const runTestsAfterBuild = () => {
  return {
    apply: (compiler) => {
      compiler.hooks.afterEmit.tap('AfterEmitPlugin', () => {
        // leave as node otherwise browser does not launch
        exec('node scripts/test-runner.js', (err, stdout, stderr) => {
          if (stdout) process.stdout.write(stdout);
          if (stderr) process.stderr.write(stderr);
        });
      });
    }
  }
};

module.exports = merge(dev, {
  mode: 'development',
  plugins: [
    new ExtensionReloader({
      // see https://github.com/SimplifyJobs/webpack-ext-reloader#usage
      entries: {
        contentScript: 'content',
        background: 'background',
        extensionPage: ['popup', 'import', 'options', 'qrdebug', 'permissions'],
      },
    }),
    runTestsAfterBuild(),
  ],
  watch: true,
  watchOptions: {
    ignored: /node_modules/
  },
  output: {
    path: path.resolve(__dirname, 'test/chrome/dist'),
    publicPath: '/test/chrome/dist/'
  }
});
