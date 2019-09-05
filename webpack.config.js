const path = require("path");

module.exports = {
  mode: "production",
  entry: path.join(__dirname, "./src/xjwt.js"),
  output: {
    path: path.join(__dirname, "./dist"),
    filename: "main.bundle.js"
  }
};
