#!/usr/bin/env node

/**
 * ============================================
 * ZK-Sentinel CLI
 * ============================================
 * 
 * Usage:
 *   node cli.js status
 *   node cli.js deposit
 *   node cli.js withdraw <note_file> <recipient> [--panic]
 *   node cli.js generate-note
 */

const { ZKSentinelSDK } = require("./zksentinel");
const path = require("path");
const fs = require("fs");

// Configuration
const CONFIG = {
    rpcUrl: process.env.RPC_URL || "https://ethereum-sepolia-rpc.publicnode.com",
    privateKey: process.env.PRIVATE_KEY || "",
    zkSentinelAddress: process.env.ZKSENTINEL_ADDRESS || "0x52Caacd09558D2d6038402ED1207932E3F5b6A3C",
    wasmPath: path.join(__dirname, "../build/withdraw_dual_js/withdraw_dual.wasm"),
    zkeyPath: path.join(__dirname, "../build/withdraw_dual_final.zkey")
};

async function main() {
    const args = process.argv.slice(2);
    const command = args[0];
    
    if (!command) {
        printHelp();
        return;
    }
    
    // Check private key for commands that need it
    if (["deposit", "withdraw"].includes(command) && !CONFIG.privateKey) {
        console.error("❌ Error: PRIVATE_KEY environment variable required");
        console.log("   Export it: export PRIVATE_KEY=0x...");
        process.exit(1);
    }
    
    const sdk = new ZKSentinelSDK(CONFIG);
    
    switch (command) {
        case "status":
            await cmdStatus(sdk);
            break;
            
        case "generate-note":
        case "generate":
            await cmdGenerateNote(sdk);
            break;
            
        case "deposit":
            await cmdDeposit(sdk, args[1]);
            break;
            
        case "withdraw":
            await cmdWithdraw(sdk, args[1], args[2], args.includes("--panic"));
            break;
            
        case "verify-note":
            await cmdVerifyNote(sdk, args[1]);
            break;
            
        case "help":
        default:
            printHelp();
    }
}

function printHelp() {
    console.log(`
╔══════════════════════════════════════════════╗
║           ZK-Sentinel CLI v1.0               ║
║   Privacy Pool with Coercion Resistance      ║
╚══════════════════════════════════════════════╝

USAGE:
  node cli.js <command> [options]

COMMANDS:
  status              Show pool status
  generate-note       Generate a new deposit note
  deposit <note>      Deposit 1 ETH using note file
  withdraw <note> <recipient> [--panic]
                      Withdraw funds to recipient
                      --panic flag uses decoy wallet (coercion mode)
  verify-note <note>  Check if note is spent

ENVIRONMENT:
  PRIVATE_KEY         Your wallet private key (required for deposit/withdraw)
  RPC_URL             RPC endpoint (default: Sepolia public node)
  ZKSENTINEL_ADDRESS  Contract address (default: deployed contract)

EXAMPLES:
  # Check pool status
  node cli.js status

  # Generate new note
  node cli.js generate-note

  # Deposit (creates and saves note)
  export PRIVATE_KEY=0x...
  node cli.js deposit

  # Normal withdrawal
  node cli.js withdraw note_1234.json 0xYourAddress

  # Coerced withdrawal (sends to decoy)
  node cli.js withdraw note_1234.json 0xYourAddress --panic
`);
}

async function cmdStatus(sdk) {
    await sdk.init();
    
    console.log("\n╔══════════════════════════════════════════════╗");
    console.log("║           ZK-Sentinel Status                 ║");
    console.log("╚══════════════════════════════════════════════╝\n");
    
    const status = await sdk.getStatus();
    
    console.log("📊 Pool Status:");
    console.log("   Contract:", CONFIG.zkSentinelAddress);
    console.log("   Denomination:", status.denomination);
    console.log("   Total Deposits:", status.totalDeposits);
    console.log("   Pool Balance:", status.poolBalance);
    console.log("   Current Root:", status.currentRoot.slice(0, 22) + "...");
    
    // Check files
    console.log("\n📁 Local Files:");
    const wasmExists = fs.existsSync(CONFIG.wasmPath);
    const zkeyExists = fs.existsSync(CONFIG.zkeyPath);
    console.log("   WASM circuit:", wasmExists ? "✅" : "❌ NOT FOUND");
    console.log("   ZKey:", zkeyExists ? "✅" : "❌ NOT FOUND");
    
    if (!wasmExists || !zkeyExists) {
        console.log("\n⚠️  Run trusted setup first:");
        console.log("   ./scripts/compile_circuits.sh");
        console.log("   ./scripts/trusted_setup.sh");
    }
}

async function cmdGenerateNote(sdk) {
    await sdk.init();
    
    console.log("\n╔══════════════════════════════════════════════╗");
    console.log("║         Generate Deposit Note                ║");
    console.log("╚══════════════════════════════════════════════╝");
    
    const note = sdk.generateNote();
    
    // Save note
    const filename = `note_${Date.now()}.json`;
    const filepath = sdk.saveNote(note, filename);
    
    console.log("\n⚠️  IMPORTANT: Keep this file safe!");
    console.log("   You need it to withdraw your funds.");
    console.log("   If lost, funds are UNRECOVERABLE.");
    
    console.log("\n📋 Next step:");
    console.log(`   node cli.js deposit ${filename}`);
}

async function cmdDeposit(sdk, noteFile) {
    await sdk.init();
    
    console.log("\n╔══════════════════════════════════════════════╗");
    console.log("║              Deposit ETH                     ║");
    console.log("╚══════════════════════════════════════════════╝");
    
    let note;
    
    if (noteFile && fs.existsSync(path.join(__dirname, "../notes", noteFile))) {
        // Load existing note
        note = sdk.loadNote(noteFile);
    } else {
        // Generate new note
        console.log("   No note file provided, generating new note...");
        note = sdk.generateNote();
    }
    
    // Confirm
    const status = await sdk.getStatus();
    console.log("\n   You will deposit:", status.denomination);
    console.log("   Commitment:", note.commitment.slice(0, 22) + "...");
    
    // Execute deposit
    const result = await sdk.deposit(note);
    
    // Save updated note with leafIndex
    const filename = noteFile || `note_${Date.now()}.json`;
    sdk.saveNote(note, filename);
    
    console.log("\n✅ Deposit successful!");
    console.log("   TX:", result.txHash);
    console.log("   Note saved:", filename);
    console.log("\n📋 To withdraw:");
    console.log(`   node cli.js withdraw ${filename} <recipient_address>`);
}

async function cmdWithdraw(sdk, noteFile, recipient, panicMode) {
    if (!noteFile || !recipient) {
        console.error("❌ Error: Missing arguments");
        console.log("   Usage: node cli.js withdraw <note_file> <recipient> [--panic]");
        process.exit(1);
    }
    
    // Validate recipient address
    if (!recipient.match(/^0x[a-fA-F0-9]{40}$/)) {
        console.error("❌ Error: Invalid recipient address");
        process.exit(1);
    }
    
    await sdk.init();
    
    console.log("\n╔══════════════════════════════════════════════╗");
    if (panicMode) {
        console.log("║     🚨 COERCED WITHDRAWAL (PANIC MODE) 🚨    ║");
    } else {
        console.log("║            Normal Withdrawal                 ║");
    }
    console.log("╚══════════════════════════════════════════════╝");
    
    // Load note
    const note = sdk.loadNote(noteFile);
    
    if (note.leafIndex === null || note.leafIndex === undefined) {
        console.error("❌ Error: Note has no leafIndex. Was it deposited?");
        process.exit(1);
    }
    
    console.log("\n   Note:", noteFile);
    console.log("   Leaf Index:", note.leafIndex);
    console.log("   Recipient:", recipient);
    console.log("   Mode:", panicMode ? "🚨 PANIC (decoy funds)" : "✅ NORMAL (real funds)");
    
    if (panicMode) {
        console.log("\n   ⚠️  PANIC MODE: Funds will go to DECOY wallet!");
        console.log("   This is for coercion resistance.");
    }
    
    // Execute withdrawal
    const result = await sdk.withdraw(note, recipient, panicMode);
    
    console.log("\n✅ Withdrawal successful!");
    console.log("   TX:", result.txHash);
    console.log("   Funds sent to:", recipient);
    
    if (panicMode) {
        console.log("\n   ℹ️  Decoy nullifier used. Real funds still available.");
        console.log("   You can withdraw real funds later with normal mode.");
    }
}

async function cmdVerifyNote(sdk, noteFile) {
    if (!noteFile) {
        console.error("❌ Error: Missing note file");
        process.exit(1);
    }
    
    await sdk.init();
    
    console.log("\n╔══════════════════════════════════════════════╗");
    console.log("║            Verify Note Status                ║");
    console.log("╚══════════════════════════════════════════════╝");
    
    const note = sdk.loadNote(noteFile);
    
    console.log("\n📝 Note Details:");
    console.log("   Commitment:", note.commitment);
    console.log("   Leaf Index:", note.leafIndex ?? "NOT DEPOSITED");
    
    // Check if deposited
    const isDeposited = await sdk.contract.commitments(note.commitment);
    console.log("   Deposited:", isDeposited ? "✅ Yes" : "❌ No");
    
    if (isDeposited) {
        // Check if spent
        const realSpent = await sdk.contract.isSpent(note.nullifierHash_real);
        const decoySpent = await sdk.contract.isSpent(note.nullifierHash_decoy);
        
        console.log("\n💰 Withdrawal Status:");
        console.log("   Real nullifier spent:", realSpent ? "✅ Yes" : "❌ No");
        console.log("   Decoy nullifier spent:", decoySpent ? "✅ Yes" : "❌ No");
        
        if (!realSpent && !decoySpent) {
            console.log("\n   ✅ Funds available for withdrawal!");
        } else if (realSpent) {
            console.log("\n   ❌ Real funds already withdrawn.");
        } else if (decoySpent) {
            console.log("\n   ⚠️  Decoy used, but real funds still available!");
        }
    }
}

// Run
main().catch(err => {
    console.error("\n❌ Error:", err.message);
    process.exit(1);
});
