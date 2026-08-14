#!/usr/bin/env node

import { checkPackage } from './agent_permit.js';

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.log('Usage: slopguard check <package-name> [--ecosystem npm|pypi]');
    process.exit(1);
  }

  const subcmd = args[0];
  if (subcmd === 'check' && args[1]) {
    const pkgName = args[1];
    let eco = 'npm';
    const ecoIdx = args.indexOf('--ecosystem');
    if (ecoIdx !== -1 && args[ecoIdx + 1]) {
      eco = args[ecoIdx + 1];
    }
    const result = await checkPackage(pkgName, eco);
    console.log(`\n🔍 SlopGuard Check: ${result.packageName} (${result.ecosystem.toUpperCase()})`);
    console.log(`Risk Score: ${result.riskScore.toFixed(1)} / 100.0`);
    console.log(`Status: ${result.isSuspicious ? '⚠️ SUSPICIOUS' : '✅ LOW RISK'}\n`);
    if (result.signals.length > 0) {
      console.log('Triggered Signals:');
      for (const sig of result.signals) {
        console.log(`  • ${sig.name}: ${sig.description}`);
      }
    } else {
      console.log('No risk signals detected.');
    }
  } else {
    console.log('Unknown or incomplete command. Try "slopguard check <package-name>"');
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
