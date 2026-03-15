#!/usr/bin/env node

import { runAuth } from './auth';

const args = process.argv.slice(2);
const command = args[0];

function printUsage(): void {
  console.log(`Usage: clawguard <command> [options]\n`);
  console.log(`Commands:`);
  console.log(`  auth <service>    Perform OAuth2 Authorization Code Flow for a service\n`);
  console.log(`Examples:`);
  console.log(`  clawguard auth msgraph`);
}

async function main(): Promise<void> {
  if (!command || command === '--help' || command === '-h') {
    printUsage();
    process.exit(command ? 0 : 1);
  }

  switch (command) {
    case 'auth': {
      const serviceName = args[1];
      if (!serviceName) {
        console.error('\u274c Missing service name.\n');
        console.error('Usage: clawguard auth <service>');
        process.exit(1);
      }
      await runAuth(serviceName);
      break;
    }
    default:
      console.error(`\u274c Unknown command: '${command}'\n`);
      printUsage();
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(`\u274c Unexpected error: ${err.message}`);
  process.exit(1);
});
