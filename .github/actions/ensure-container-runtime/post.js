// Cleanup runs before Actions kills job processes, while the private namespace lives.
const { spawnSync } = require("node:child_process");
const { join } = require("node:path");

const result = spawnSync("bash", [join(__dirname, "cleanup.sh")], { stdio: "inherit" });
if (result.error) {
  console.error(result.error.message);
}
process.exitCode = result.status === 0 ? 0 : result.status || 1;
