function readCFG (file) {
  var reader = new FileReader();
  let content = reader.readAsText(file);
  return content;
}

console.log(readCFG("./config.ini"));
