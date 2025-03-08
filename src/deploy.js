const ghpages = require("gh-pages");

ghpages.publish("dist", function (err) {
  if (err) {
    console.error("Deploy failed! \n" + err);
    return;
  }
  console.log("Deployed successfully!");
});
