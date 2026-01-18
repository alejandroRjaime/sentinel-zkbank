#!/usr/bin/env node

/**
 * ============================================
 * ZK-Sentinel: End-to-End Demo
 * ============================================
 * 
 * Demonstrates complete flow:
 * 1. Generate note
 * 2. Deposit 0.01 ETH
 * 3. Generate ZK proof
 * 4. Withdraw (normal)
 * 5. Show panic mode (optional)
 * 
 * Usage:
 *   export PRIVATE_KEY=0x...
 *   node demo.js
 *   node demo.js --dry-run  (no transactions)
 */

const { ZKSentinelSDK } = require("./zksentinel");
const { ethers } = require("ethers");
const path = require("path");
const readline = require("readline");

const CONFIG = {
    rpcUrl: process.env.RPC_URL || "https://ethereum-sepolia-rpc.publicnode.com",
    privateKey: process.env.PRIVATE_KEY || "",
    zkSentinelAddress: process.env.ZKSENTINEL_ADDRESS || "0x52Caacd09558D2d6038402ED1207932E3F5b6A3C",
    wasmPath: path.join(__dirname, "../build/withdraw_dual_js/withdraw_dual.wasm"),
    zkeyPath: path.join(__dirname, "../build/withdraw_dual_final.zkey")
};

const DRY_RUN = process.argv.includes("--dry-run");

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function prompt(question) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    return new Promise(resolve => {
        rl.question(question, answer => {
            rl.close();
            resolve(answer);
        });
    });
}

async function main() {
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║            ZK-Sentinel End-to-End Demo                       ║
║                                                              ║
║   Privacy Pool with Mathematical Indistinguishability        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
`);

    if (DRY_RUN) {
        console.log("🔸 DRY RUN MODE - No transactions will be sent\n");
    }
    
    // Check private key
    if (!CONFIG.privateKey && !DRY_RUN) {
        console.log("❌ PRIVATE_KEY not set!");
        console.log("   Run: export PRIVATE_KEY=0x...\n");
        process.exit(1);
    }
    
    // Initialize SDK
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.log("STEP 0: Initialize SDK");
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    const sdk = new ZKSentinelSDK(CONFIG);
    await sdk.init();
    
    // Show status
    const status = await sdk.getStatus();
    console.log("\n📊 Current Pool Status:");
    console.log("   Total Deposits:", status.totalDeposits);
    console.log("   Pool Balance:", status.poolBalance);
    
    // ============ STEP 1: Generate Note ============
    console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.log("STEP 1: Generate Deposit Note");
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    console.log("Generating cryptographic note with:");
    console.log("  - Secret (random 256-bit)");
    console.log("  - Real nullifier (for normal withdrawal)");
    console.log("  - Decoy nullifier (for coerced withdrawal)");
    
    const note = sdk.generateNote();
    
    console.log("\n✅ Note generated!");
    console.log("   This note contains the secrets needed to withdraw.");
    
    // Save note
    const noteFile = `demo_note_${Date.now()}.json`;
    sdk.saveNote(note, noteFile);
    
    if (DRY_RUN) {
        console.log("\n🔸 [DRY RUN] Skipping deposit...\n");
    } else {
        // ============ STEP 2: Deposit ============
        console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        console.log("STEP 2: Deposit 0.01 ETH");
        console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        
        const balance = await sdk.provider.getBalance(sdk.signer.address);
        console.log("Your balance:", ethers.formatEther(balance), "ETH");
        
        if (balance < ethers.parseEther("0.011")) {
            console.log("\n⚠️  Insufficient balance for demo (need > 0.010.01 ETH)");
            console.log("   Get Sepolia ETH from: https://sepoliafaucet.com/\n");
            process.exit(1);
        }
        
        const answer = await prompt("\nProceed with deposit? (y/n): ");
        if (answer.toLowerCase() !== "y") {
            console.log("Aborted.");
            process.exit(0);
        }
        
        console.log("\nDepositing 0.01 ETH...");
        console.log("The commitment goes into the Merkle tree on-chain.\n");
        
        const depositResult = await sdk.deposit(note);
        
        // Update saved note
        sdk.saveNote(note, noteFile);
        
        console.log("\n✅ Deposit successful!");
        console.log("   Your funds are now in the privacy pool.");
        console.log("   Leaf index:", note.leafIndex);
        
        // Wait for indexing
        console.log("\nWaiting 5 seconds for chain to settle...");
        await sleep(5000);
        
        // ============ STEP 3: Withdraw ============
        console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        console.log("STEP 3: Withdraw (Normal Mode)");
        console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        
        console.log("Now we'll withdraw using a ZK proof.");
        console.log("The proof proves we know the secret WITHOUT revealing it.\n");
        
        const recipient = sdk.signer.address;
        console.log("Recipient:", recipient);
        console.log("Mode: NORMAL (real funds)");
        
        const answer2 = await prompt("\nProceed with withdrawal? (y/n): ");
        if (answer2.toLowerCase() !== "y") {
            console.log("Aborted. Your note is saved:", noteFile);
            process.exit(0);
        }
        
        console.log("\n");
        const withdrawResult = await sdk.withdraw(note, recipient, false);
        
        console.log("\n✅ Withdrawal successful!");
        console.log("   Funds returned to:", recipient);
    }
    
    // ============ Explain Panic Mode ============
    console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.log("BONUS: Panic Mode (Coercion Resistance)");
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    console.log(`
🚨 What is Panic Mode?

If you're being COERCED to withdraw (e.g., $5 wrench attack),
you can use --panic flag:

   node cli.js withdraw ${noteFile} 0xAttacker --panic

This produces a VALID proof that:
  ✅ Passes all verification
  ✅ Sends funds to the attacker
  ❌ BUT uses the DECOY nullifier

The attacker CANNOT tell the difference!
Your REAL funds remain safe for later withdrawal.

┌─────────────────────────────────────────────────────────┐
│  This is MATHEMATICAL INDISTINGUISHABILITY.             │
│  The ZK proof is identical in both modes.               │
│  On-chain footprint is identical.                       │
│  No one can prove which mode was used.                  │
└─────────────────────────────────────────────────────────┘
`);
    
    // ============ Final Status ============
    console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.log("DEMO COMPLETE");
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    if (!DRY_RUN) {
        const finalStatus = await sdk.getStatus();
        console.log("📊 Final Pool Status:");
        console.log("   Total Deposits:", finalStatus.totalDeposits);
        console.log("   Pool Balance:", finalStatus.poolBalance);
    }
    
    console.log("\n📁 Files:");
    console.log("   Note saved:", `notes/${noteFile}`);
    
    console.log("\n📚 Commands:");
    console.log("   node cli.js status              - Check pool status");
    console.log("   node cli.js verify-note <file>  - Check if note is spent");
    console.log("   node cli.js deposit             - Make new deposit");
    console.log("   node cli.js withdraw <note> <addr> [--panic]");
    
    console.log("\n");
}

main().catch(err => {
    console.error("\n❌ Error:", err.message);
    if (err.message.includes("ENOENT")) {
        console.log("\n⚠️  Circuit files not found!");
        console.log("   Run trusted setup first:");
        console.log("   ./scripts/compile_circuits.sh");
        console.log("   ./scripts/trusted_setup.sh");
    }
    process.exit(1);
});
