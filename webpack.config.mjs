import path from 'path';
import TerserPlugin from 'terser-webpack-plugin';
import { BundleAnalyzerPlugin } from 'webpack-bundle-analyzer';
import MiniCssExtractPlugin from 'mini-css-extract-plugin';
import CssMinimizerPlugin from 'css-minimizer-webpack-plugin';
import CopyWebpackPlugin from 'copy-webpack-plugin';

export default (env, argv) => {
  const isAnalyze = env && env.analyze;
  const isDevelopment = argv.mode === 'development';
  const target = env && env.target === 'firefox' ? 'firefox' : 'chrome';

  // Set output directory based on browser target
  const outputDir = path.join('extension', target);

  return {
    entry: {
      core: './src/core.ts',
      injector: './src/injector.ts',
      background: './src/background.ts',
      dispatcher: './src/dispatcher.ts',
      menu: {
        import: [
          './src/menu.ts',
          './src/settings.ts',
          './src/styles/main.css'
        ],
      },
      popup: './src/popup.ts'
    },
    module: {
      rules: [
        {
          test: /\.ts$/,
          use: [
            {
              loader: 'ts-loader',
              options: {
                transpileOnly: true,
                compilerOptions: {
                  module: 'esnext',
                },
              },
            },
          ],
          exclude: /node_modules/,
        },
        {
          test: /\.css$/,
          use: [
            MiniCssExtractPlugin.loader,
            {
              loader: 'css-loader',
              options: {
                import: true,
                importLoaders: 1,
              }
            },
          ],
        },
      ],
    },
    resolve: {
      extensions: ['.ts', '.css'],
      // Use browser-specific API implementation based on target
      alias: {
        'browser-api': path.resolve(
          process.cwd(), 
          `src/browser-api/${target}.ts`
        )
      }
    },
    output: {
      filename: '[name].js',
      path: path.resolve(process.cwd(), outputDir),
    },
    plugins: [
      // Modify MiniCssExtractPlugin to create popup.css and menu.css
      new MiniCssExtractPlugin({
        filename: ({ chunk }) => {
          return chunk.name === 'popup' ? 'popup.css' : 'menu.css';
        },
      }),
      new CopyWebpackPlugin({
        patterns: [
          // Copy all files from assets except manifests
          {
            from: 'assets',
            globOptions: {
              ignore: [
                '**/manifest.*.json'
              ]
            }
          },
          // Copy target-specific manifest and rename it to manifest.json
          {
            from: `assets/manifest.${target}.json`,
            to: 'manifest.json'
          }
        ],
      }),
      ...(isAnalyze ? [new BundleAnalyzerPlugin()] : []),
    ],
    optimization: {
      usedExports: true,
      minimize: argv.mode === 'production',
      minimizer: [
        new TerserPlugin({
          extractComments: false,
          terserOptions: {
            format: {
              comments: false,
            },
          },
        }),
        new CssMinimizerPlugin(),
      ],
    },
    mode: isDevelopment ? 'development' : 'production',
    devtool: isDevelopment ? 'inline-source-map' : false,
    watch: isDevelopment,
    watchOptions: {
      ignored: /node_modules/,
    },
  };
};