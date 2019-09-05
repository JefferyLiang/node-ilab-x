const path = require("path");

module.exports = {
  entry: path.join(__dirname, "./src/xjwt.js"),
  output: {
    path: path.join(__dirname, "./dist"),
    filename: "main.bundle.js"
  }
};
