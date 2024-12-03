import path from 'path';
import TerserPlugin from 'terser-webpack-plugin';
import { BundleAnalyzerPlugin } from 'webpack-bundle-analyzer';
import MiniCssExtractPlugin from 'mini-css-extract-plugin';
import CssMinimizerPlugin from 'css-minimizer-webpack-plugin';

export default (env, argv) => {
  const isAnalyze = env && env.analyze;
  const isDevelopment = argv.mode === 'development';

  return {
    entry: {
      core: './src/core.ts',
      injector: './src/injector.ts',
      background: './src/background.ts',
      dispatcher: './src/dispatcher.ts',
      menu: {
        import: ['./src/menu.ts', './src/styles.css'],
      },
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
            'css-loader'
          ],
        },
      ],
    },
    resolve: {
      extensions: ['.ts', '.css'],
    },
    output: {
      filename: '[name].js',
      path: path.resolve(process.cwd(), 'extension'),
    },
    plugins: [
      new MiniCssExtractPlugin({
        filename: 'styles.css'
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