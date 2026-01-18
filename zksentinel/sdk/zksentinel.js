/**
 * ============================================
 * ZK-Sentinel SDK
 * ============================================
 * 
 * SDK para interactuar con ZK-Sentinel:
 * - Generar commitments
 * - Hacer deposits
 * - Generar ZK proofs
 * - Hacer withdrawals (normal y bajo coerción)
 */

const { ethers } = require("ethers");
const snarkjs = require("snarkjs");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const { buildPoseidon } = require("circomlibjs");

class ZKSentinelSDK {
    constructor(config) {
        this.rpcUrl = config.rpcUrl;
        this.privateKey = config.privateKey;
        this.zkSentinelAddress = config.zkSentinelAddress;
        
        this.wasmPath = config.wasmPath || path.join(__dirname, "../build/withdraw_dual_js/withdraw_dual.wasm");
        this.zkeyPath = config.zkeyPath || path.join(__dirname, "../build/withdraw_dual_final.zkey");
        
        this.provider = null;
        this.signer = null;
        this.contract = null;
        this.poseidon = null;
        this.F = null;
        
        // Merkle tree config
        this.MERKLE_LEVELS = 20;
        this.ZERO_VALUE = BigInt(0);
        
        // Contract ABI
        this.ABI = [
            "function deposit(bytes32 _commitment) external payable",
            "function withdraw(uint256[2] calldata _pA, uint256[2][2] calldata _pB, uint256[2] calldata _pC, bytes32 _root, bytes32 _nullifierHash, address payable _recipient, address payable _relayer, uint256 _fee) external",
            "function getLastRoot() external view returns (bytes32)",
            "function isSpent(bytes32 _nullifierHash) external view returns (bool)",
            "function isKnownRoot(bytes32 _root) external view returns (bool)",
            "function commitments(bytes32) external view returns (bool)",
            "function DENOMINATION() external view returns (uint256)",
            "function nextIndex() external view returns (uint32)",
            "event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp)"
        ];
    }
    
    /**
     * Initialize SDK (must call before using)
     */
    async init() {
        console.log("Initializing ZK-Sentinel SDK...");
        
        // Setup ethers
        this.provider = new ethers.JsonRpcProvider(this.rpcUrl);
        this.signer = new ethers.Wallet(this.privateKey, this.provider);
        this.contract = new ethers.Contract(this.zkSentinelAddress, this.ABI, this.signer);
        
        // Setup Poseidon
        this.poseidon = await buildPoseidon();
        this.F = this.poseidon.F;
        
        // Precompute zero hashes for Merkle tree
        this.zeros = this._computeZeros();
        
        console.log("SDK Ready!");
        console.log("  Address:", this.signer.address);
        console.log("  Contract:", this.zkSentinelAddress);
        
        return this;
    }
    
    // ============ CRYPTO UTILITIES ============
    
    _randomBigInt(nBytes = 31) {
        return BigInt("0x" + crypto.randomBytes(nBytes).toString("hex"));
    }
    
    _poseidonHash(inputs) {
        const hash = this.poseidon(inputs.map(x => this.F.e(x)));
        return this.F.toObject(hash);
    }
    
    _toHex32(value) {
        return "0x" + BigInt(value).toString(16).padStart(64, "0");
    }
    
    _computeZeros() {
        const zeros = [this.ZERO_VALUE];
        for (let i = 1; i <= this.MERKLE_LEVELS; i++) {
            zeros[i] = this._poseidonHash([zeros[i-1], zeros[i-1]]);
        }
        return zeros;
    }
    
    // ============ NOTE MANAGEMENT ============
    
    /**
     * Generate a new deposit note
     * @returns {Object} Note with secret, nullifiers, commitment
     */
    generateNote() {
        const secret = this._randomBigInt();
        const nullifier_real = this._randomBigInt();
        const nullifier_decoy = this._randomBigInt();
        
        // commitment = Poseidon(secret, nullifier_real)
        const commitment = this._poseidonHash([secret, nullifier_real]);
        const nullifierHash_real = this._poseidonHash([nullifier_real]);
        const nullifierHash_decoy = this._poseidonHash([nullifier_decoy]);
        
        const note = {
            secret: secret.toString(),
            nullifier_real: nullifier_real.toString(),
            nullifier_decoy: nullifier_decoy.toString(),
            commitment: this._toHex32(commitment),
            nullifierHash_real: this._toHex32(nullifierHash_real),
            nullifierHash_decoy: this._toHex32(nullifierHash_decoy),
            leafIndex: null,
            timestamp: Date.now()
        };
        
        console.log("\n📝 Generated Note:");
        console.log("   Commitment:", note.commitment.slice(0, 18) + "...");
        console.log("   NullifierHash (real):", note.nullifierHash_real.slice(0, 18) + "...");
        console.log("   NullifierHash (decoy):", note.nullifierHash_decoy.slice(0, 18) + "...");
        
        return note;
    }
    
    /**
     * Save note to file
     */
    saveNote(note, filename) {
        const notesDir = path.join(__dirname, "../notes");
        fs.mkdirSync(notesDir, { recursive: true });
        
        const filepath = path.join(notesDir, filename);
        fs.writeFileSync(filepath, JSON.stringify(note, null, 2));
        console.log("💾 Note saved:", filepath);
        return filepath;
    }
    
    /**
     * Load note from file
     */
    loadNote(filename) {
        const filepath = path.join(__dirname, "../notes", filename);
        const note = JSON.parse(fs.readFileSync(filepath, "utf-8"));
        console.log("📂 Note loaded:", note.commitment.slice(0, 18) + "...");
        return note;
    }
    
    // ============ DEPOSIT ============
    
    /**
     * Deposit ETH into ZK-Sentinel
     * @param {Object} note - Note from generateNote()
     */
    async deposit(note) {
        console.log("\n💰 === DEPOSIT ===");
        
        // Get denomination
        const denomination = await this.contract.DENOMINATION();
        console.log("   Amount:", ethers.formatEther(denomination), "ETH");
        
        // Check balance
        const balance = await this.provider.getBalance(this.signer.address);
        if (balance < denomination) {
            throw new Error(`Insufficient balance. Need ${ethers.formatEther(denomination)} ETH`);
        }
        
        // Check if commitment exists
        const exists = await this.contract.commitments(note.commitment);
        if (exists) {
            throw new Error("Commitment already exists!");
        }
        
        // Send transaction
        console.log("   Sending transaction...");
        const tx = await this.contract.deposit(note.commitment, { value: denomination });
        console.log("   TX:", tx.hash);
        
        const receipt = await tx.wait();
        console.log("   ✅ Confirmed in block:", receipt.blockNumber);
        
        // Parse event for leaf index
        for (const log of receipt.logs) {
            try {
                const parsed = this.contract.interface.parseLog(log);
                if (parsed.name === "Deposit") {
                    note.leafIndex = Number(parsed.args.leafIndex);
                    console.log("   Leaf Index:", note.leafIndex);
                }
            } catch {}
        }
        
        return { txHash: tx.hash, receipt, note };
    }
    
    // ============ MERKLE TREE ============
    
    /**
     * Get all deposits from events and build Merkle tree
     */
    async getDeposits() {
        console.log("\n🌳 Fetching deposits...");
        
        const filter = this.contract.filters.Deposit();
        const events = await this.contract.queryFilter(filter, 10072000, "latest");
        
        const deposits = events.map(e => ({
            commitment: e.args.commitment,
            leafIndex: Number(e.args.leafIndex),
            timestamp: Number(e.args.timestamp)
        }));
        
        console.log("   Found", deposits.length, "deposits");
        return deposits;
    }
    
    /**
     * Build Merkle tree and get path for a leaf
     */
    async getMerklePath(leafIndex, commitment) {
        console.log("\n🔐 Building Merkle path for leaf", leafIndex);
        
        // Get all deposits
        const deposits = await this.getDeposits();
        
        // Build tree leaves
        const leaves = new Array(2 ** this.MERKLE_LEVELS).fill(this.ZERO_VALUE);
        for (const dep of deposits) {
            leaves[dep.leafIndex] = BigInt(dep.commitment);
        }
        
        // Build tree layers and collect path
        const pathElements = [];
        const pathIndices = [];
        
        let currentLayer = leaves;
        let idx = leafIndex;
        
        for (let level = 0; level < this.MERKLE_LEVELS; level++) {
            const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
            const sibling = currentLayer[siblingIdx] || this.zeros[level];
            
            pathElements.push(sibling.toString());
            pathIndices.push((idx % 2).toString());
            
            // Build next layer
            const nextLayer = [];
            for (let i = 0; i < currentLayer.length; i += 2) {
                const left = currentLayer[i] || this.zeros[level];
                const right = currentLayer[i + 1] || this.zeros[level];
                nextLayer.push(this._poseidonHash([left, right]));
            }
            currentLayer = nextLayer;
            idx = Math.floor(idx / 2);
        }
        
        const root = this._toHex32(currentLayer[0]);
        console.log("   Computed root:", root.slice(0, 18) + "...");
        
        // Verify root is known
        const isKnown = await this.contract.isKnownRoot(root);
        console.log("   Root known on-chain:", isKnown);
        
        return { pathElements, pathIndices, root };
    }
    
    // ============ PROOF GENERATION ============
    
    /**
     * Generate ZK proof for withdrawal
     * @param {Object} note - The deposit note
     * @param {string} recipient - Address to receive funds
     * @param {boolean} panicMode - true = use decoy (coerced), false = normal
     */
    async generateProof(note, recipient, panicMode = false) {
        console.log("\n🔮 === GENERATING PROOF ===");
        console.log("   Mode:", panicMode ? "🚨 PANIC (decoy)" : "✅ NORMAL");
        console.log("   Recipient:", recipient);
        
        // Get Merkle path
        const { pathElements, pathIndices, root } = await this.getMerklePath(
            note.leafIndex,
            note.commitment
        );
        
        // Build circuit input
        const input = {
            // Private inputs
            secret: note.secret,
            nullifier_real: note.nullifier_real,
            nullifier_decoy: note.nullifier_decoy,
            pathElements: pathElements,
            pathIndices: pathIndices,
            panic_bit: panicMode ? "1" : "0",
            ia_inference: "0",  // ZKML output (hardcoded for now)
            
            // Public inputs
            root: BigInt(root).toString(),
            recipient: BigInt(recipient).toString()
        };
        
        console.log("   Generating SNARK proof...");
        const startTime = Date.now();
        
        // Generate proof
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            this.wasmPath,
            this.zkeyPath
        );
        
        const proofTime = Date.now() - startTime;
        console.log("   ⏱️  Proof generated in", proofTime, "ms");
        
        // The nullifierHash output depends on panic_bit
        const nullifierHash = this._toHex32(publicSignals[0]);
        console.log("   NullifierHash:", nullifierHash.slice(0, 18) + "...");
        
        // Format proof for Solidity
        const solidityProof = {
            pA: [proof.pi_a[0], proof.pi_a[1]],
            pB: [
                [proof.pi_b[0][1], proof.pi_b[0][0]],
                [proof.pi_b[1][1], proof.pi_b[1][0]]
            ],
            pC: [proof.pi_c[0], proof.pi_c[1]],
            root: root,
            nullifierHash: nullifierHash
        };
        
        return solidityProof;
    }
    
    // ============ WITHDRAW ============
    
    /**
     * Withdraw funds from ZK-Sentinel
     * @param {Object} note - The deposit note
     * @param {string} recipient - Address to receive funds
     * @param {boolean} panicMode - true = use decoy wallet
     * @param {string} relayer - Relayer address (optional)
     * @param {BigInt} fee - Relayer fee (optional)
     */
    async withdraw(note, recipient, panicMode = false, relayer = null, fee = 0n) {
        console.log("\n💸 === WITHDRAW ===");
        
        // Check if already spent
        const expectedNullifier = panicMode ? note.nullifierHash_decoy : note.nullifierHash_real;
        const isSpent = await this.contract.isSpent(expectedNullifier);
        if (isSpent) {
            throw new Error("Note already spent!");
        }
        
        // Generate proof
        const proof = await this.generateProof(note, recipient, panicMode);
        
        // Send transaction
        console.log("\n   Sending withdraw transaction...");
        const tx = await this.contract.withdraw(
            proof.pA,
            proof.pB,
            proof.pC,
            proof.root,
            proof.nullifierHash,
            recipient,
            relayer || ethers.ZeroAddress,
            fee
        );
        
        console.log("   TX:", tx.hash);
        const receipt = await tx.wait();
        console.log("   ✅ Withdrawal confirmed in block:", receipt.blockNumber);
        
        return { txHash: tx.hash, receipt, proof };
    }
    
    // ============ VIEW FUNCTIONS ============
    
    async getStatus() {
        const denomination = await this.contract.DENOMINATION();
        const nextIndex = await this.contract.nextIndex();
        const root = await this.contract.getLastRoot();
        const balance = await this.provider.getBalance(this.zkSentinelAddress);
        
        return {
            denomination: ethers.formatEther(denomination) + " ETH",
            totalDeposits: Number(nextIndex),
            currentRoot: root,
            poolBalance: ethers.formatEther(balance) + " ETH"
        };
    }
}

module.exports = { ZKSentinelSDK };
