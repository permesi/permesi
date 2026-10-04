// Run the same locally testable scripts and register a cleanup hook for this job.
const { spawnSync } = require("node:child_process");
const { join } = require("node:path");

for (const [command, script] of [
  ["python3", "test_runtime.py"],
  ["bash", "runtime.sh"],
]) {
  const result = spawnSync(command, [join(__dirname, script)], { stdio: "inherit" });
  if (result.error) {
    console.error(result.error.message);
  }
  if (result.status !== 0) {
    process.exit(result.status || 1);
  }
}
