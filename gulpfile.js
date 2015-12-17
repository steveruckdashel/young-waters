'use strict';

var gulp = require('gulp');
var gutil = require("gulp-util");
var sass = require('gulp-sass');
var sourcemaps = require('gulp-sourcemaps');
var del = require('del'); // rm -rf
var webpack = require("webpack");

gulp.task('default', ['assets', 'style', 'webpack']);

gulp.task('assets', function () {
  gulp.src('./unmanaged/salesforce-lightning-design-system-v0.8.0/assets/**/*.*')
    .pipe(gulp.dest('./wwwroot/assets'));
});

gulp.task('style', ['sass', 'css']);

gulp.task('css', function() {
  gulp.src(['./node_modules/fixed-data-table/dist/*.min.css'])
    .pipe(gulp.dest('./wwwroot/css'));
});

gulp.task('sass', function () {
  gulp.src('./node_modules/@salesforce-ux/design-system/scss/index.scss')
    .pipe(sourcemaps.init())
      .pipe(sass().on('error', sass.logError))
    .pipe(sourcemaps.write('./wwwroot/maps'))
    .pipe(gulp.dest('./wwwroot/css'));
});

gulp.task("webpack", function(callback) {
    // run webpack
    webpack({
        entry: "./scripts/app.jsx",
        output: {
            path: "./wwwroot/js",
            filename: "bundle.js"
        },
        module: {
            loaders: [
                {
                  test: /\.jsx?$/,
                  exclude: /(node_modules|bower_components)/,
                  loader: 'babel'
                },
            ],
            plugins: [
              new webpack.optimize.UglifyJsPlugin([])
            ]
          }
      }, function(err, stats) {
          if(err) throw new gutil.PluginError("webpack", err);
          gutil.log("[webpack]", stats.toString({
              // output options
          }));
          callback();
      });
});

gulp.task('clean', function() {
    return del(['./wwwroot']);
});