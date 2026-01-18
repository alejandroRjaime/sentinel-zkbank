pragma circom 2.1.6;

/**
 * ============================================
 * ZK-Sentinel: Arithmetic Selector
 * ============================================
 * 
 * KEY COMPONENT for mathematical indistinguishability.
 * Selects between two values using pure arithmetic.
 * 
 * Formula: out = in[0] + sel * (in[1] - in[0])
 *   - If sel = 0: out = in[0]
 *   - If sel = 1: out = in[1]
 * 
 * SECURITY: No branching, proof reveals nothing about sel.
 */
template Selector() {
    signal input in[2];
    signal input sel;
    signal output out;
    
    // Constraint: sel must be binary
    sel * (sel - 1) === 0;
    
    // Arithmetic selection
    signal diff;
    diff <== in[1] - in[0];
    out <== in[0] + sel * diff;
}

/**
 * Binary OR: out = a + b - a*b
 */
template OR() {
    signal input a;
    signal input b;
    signal output out;
    
    a * (a - 1) === 0;
    b * (b - 1) === 0;
    
    out <== a + b - a * b;
}

/**
 * Binary AND: out = a * b
 */
template AND() {
    signal input a;
    signal input b;
    signal output out;
    
    a * (a - 1) === 0;
    b * (b - 1) === 0;
    
    out <== a * b;
}
