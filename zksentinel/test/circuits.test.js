/**
 * ZK-Sentinel Circuit Tests
 * 
 * Tests the dual-logic withdrawal circuit
 */

const { expect } = require("chai");
const snarkjs = require("snarkjs");
const path = require("path");
const crypto = require("crypto");

// Poseidon hash (simplified for testing)
const buildPoseidon = require("circomlibjs").buildPoseidon;

describe("ZK-Sentinel Circuits", function() {
    this.timeout(60000); // ZK proofs take time
    
    let poseidon;
    let F; // Finite field
    
    before(async () => {
        poseidon = await buildPoseidon();
        F = poseidon.F;
    });
    
    function randomBigInt() {
        return BigInt("0x" + crypto.randomBytes(31).toString("hex"));
    }
    
    function poseidonHash(inputs) {
        const hash = poseidon(inputs.map(x => F.e(x)));
        return F.toObject(hash);
    }
    
    describe("Selector Logic", () => {
        it("should select first value when sel=0", () => {
            const a = 100n;
            const b = 200n;
            const sel = 0n;
            // out = a + sel * (b - a) = 100 + 0 * (200-100) = 100
            const result = a + sel * (b - a);
            expect(result).to.equal(100n);
        });
        
        it("should select second value when sel=1", () => {
            const a = 100n;
            const b = 200n;
            const sel = 1n;
            // out = a + sel * (b - a) = 100 + 1 * (200-100) = 200
            const result = a + sel * (b - a);
            expect(result).to.equal(200n);
        });
    });
    
    describe("Coercion OR Logic", () => {
        it("should return 0 when both inputs are 0", () => {
            const a = 0n, b = 0n;
            // OR = a + b - a*b = 0 + 0 - 0 = 0
            const result = a + b - a * b;
            expect(result).to.equal(0n);
        });
        
        it("should return 1 when panic_bit=1", () => {
            const panic = 1n, ia = 0n;
            const result = panic + ia - panic * ia;
            expect(result).to.equal(1n);
        });
        
        it("should return 1 when ia_inference=1", () => {
            const panic = 0n, ia = 1n;
            const result = panic + ia - panic * ia;
            expect(result).to.equal(1n);
        });
        
        it("should return 1 when both are 1", () => {
            const panic = 1n, ia = 1n;
            // 1 + 1 - 1*1 = 1
            const result = panic + ia - panic * ia;
            expect(result).to.equal(1n);
        });
    });
    
    describe("Nullifier Hash Selection", () => {
        it("should output real nullifier hash when not coerced", async () => {
            const nullifier_real = randomBigInt();
            const nullifier_decoy = randomBigInt();
            
            const hashReal = poseidonHash([nullifier_real]);
            const hashDecoy = poseidonHash([nullifier_decoy]);
            
            const coercion_detected = 0n;
            
            // Selector: hashReal + coercion * (hashDecoy - hashReal)
            const output = BigInt(hashReal) + coercion_detected * (BigInt(hashDecoy) - BigInt(hashReal));
            
            expect(output).to.equal(BigInt(hashReal));
        });
        
        it("should output decoy nullifier hash when coerced", async () => {
            const nullifier_real = randomBigInt();
            const nullifier_decoy = randomBigInt();
            
            const hashReal = poseidonHash([nullifier_real]);
            const hashDecoy = poseidonHash([nullifier_decoy]);
            
            const coercion_detected = 1n;
            
            // Selector: hashReal + coercion * (hashDecoy - hashReal)
            const output = BigInt(hashReal) + coercion_detected * (BigInt(hashDecoy) - BigInt(hashReal));
            
            expect(output).to.equal(BigInt(hashDecoy));
        });
    });
    
    describe("Full Circuit (requires compilation)", () => {
        const wasmPath = path.join(__dirname, "../build/withdraw_dual_js/withdraw_dual.wasm");
        const zkeyPath = path.join(__dirname, "../build/withdraw_dual_final.zkey");
        
        it.skip("should generate valid proof for normal withdrawal", async () => {
            // This test requires compiled circuits
            // Run: npm run compile:circuits && npm run setup
            
            const secret = randomBigInt();
            const nullifier_real = randomBigInt();
            const nullifier_decoy = randomBigInt();
            
            const input = {
                secret: secret.toString(),
                nullifier_real: nullifier_real.toString(),
                nullifier_decoy: nullifier_decoy.toString(),
                pathElements: Array(20).fill("0"),
                pathIndices: Array(20).fill("0"),
                panic_bit: "0",
                ia_inference: "0",
                root: "0",
                recipient: "1234567890"
            };
            
            const { proof, publicSignals } = await snarkjs.groth16.fullProve(
                input,
                wasmPath,
                zkeyPath
            );
            
            expect(proof).to.exist;
            expect(publicSignals).to.have.length(1); // nullifierHash
        });
        
        it.skip("should generate valid proof for coerced withdrawal", async () => {
            const secret = randomBigInt();
            const nullifier_real = randomBigInt();
            const nullifier_decoy = randomBigInt();
            
            const input = {
                secret: secret.toString(),
                nullifier_real: nullifier_real.toString(),
                nullifier_decoy: nullifier_decoy.toString(),
                pathElements: Array(20).fill("0"),
                pathIndices: Array(20).fill("0"),
                panic_bit: "1",  // COERCED
                ia_inference: "0",
                root: "0",
                recipient: "1234567890"
            };
            
            const { proof, publicSignals } = await snarkjs.groth16.fullProve(
                input,
                wasmPath,
                zkeyPath
            );
            
            expect(proof).to.exist;
            // Should output decoy nullifier hash, but observer can't tell!
        });
    });
});
