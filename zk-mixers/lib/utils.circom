pragma circom 2.1.5;

include "../constants/constants.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/*
 * Utilidades matemáticas y de verificación
 */

// Verificador de rango usando lookup tables
template RangeCheck(bits) {
    signal input in;
    signal output out;

    component bitsConverter = Num2Bits(bits);
    bitsConverter.in <== in;

    // La conversión exitosa implica que está en rango
    out <== 1;
}

// Verificador de rango con límites específicos
template BoundedRangeCheck(min, max) {
    signal input in;
    signal output isValid;

    component lessThanMax = LessThan(64);
    component greaterThanMin = GreaterThan(64);

    lessThanMax.in[0] <== in;
    lessThanMax.in[1] <== max;

    greaterThanMin.in[0] <== in;
    greaterThanMin.in[1] <== min;

    isValid <== lessThanMax.out * greaterThanMin.out;
}

// Suma segura con detección de overflow
template SafeAdder(bits) {
    signal input a;
    signal input b;
    signal output sum;
    signal output overflow;

    component num2bitsA = Num2Bits(bits);
    component num2bitsB = Num2Bits(bits);
    component num2bitsSum = Num2Bits(bits + 1);

    num2bitsA.in <== a;
    num2bitsB.in <== b;

    signal sumExtended <== a + b;
    num2bitsSum.in <== sumExtended;

    sum <== sumExtended;
    overflow <== num2bitsSum.out[bits];
}

// Resta segura con detección de underflow
template SafeSubtractor(bits) {
    signal input a;
    signal input b;
    signal output difference;
    signal output underflow;

    component lessThan = LessThan(bits);

    lessThan.in[0] <== a;
    lessThan.in[1] <== b;

    underflow <== lessThan.out;
    difference <== a - b;
}

// Verificador de divisibilidad
template IsDivisibleBy(divisor) {
    signal input in;
    signal output isDivisible;

    // Calcular residuo
    signal remainder <== in % divisor;

    // Verificar si es cero
    isDivisible <== (remainder == 0) ? 1 : 0;
}

// Comparador de igualdad constante
template IsEqual(to) {
    signal input in;
    signal output out;

    out <== (in == to) ? 1 : 0;
}

// Selector multiplexor
template Mux() {
    signal input sel;  // 0 o 1
    signal input in0;
    signal input in1;
    signal output out;

    out <== (sel == 0) ? in0 : in1;
}

// Conversor de boolean a signal
template BoolToSignal() {
    signal input in;
    signal output out;

    out <== in ? 1 : 0;
}