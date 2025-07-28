# Version 0.13

'''
Changelog

21/07/2025
1) seperated Multi points verification from core kzg - Jeremy
2) imported an image to showcase large SRS generation is a disaster - Jeremy
3) tidy up format a bit. node old codes are in the next code cell.

17/07/2025
1) import secrets - Sabine

15/07/2025
1) additive homomorphism - ngonk

'''

import secrets
# from py_ecc.bls12_381 import G1, G2, Z1, curve_order, add, multiply, pairing, neg

# --------------------------------
# Run on optimized_bls12_381
# - use projective coeffs
# - optimized algorithms no division needed
# - written in Python + Cython
# - Final exponentiation optimized pairing
# - faster
# - Normalization needed for equality checks
# --------------------------------
from py_ecc.optimized_bls12_381 import (
    G1, Z1,
    curve_order,
    add,
    multiply,
    neg,
    pairing,
    final_exponentiate,
)

DEBUG_OUTPUT = 0 # 0 or 1

class Kzg:

    def __init__(self):
        pass

    # --------------------------------
    # Convert data into fx
    # --------------------------------

    # Msg such as "I like cats and dogs."
    def msg_to_coeffs(self, msg):
        msg_bytes = msg.encode()
        return self.data_to_coeffs(msg_bytes)
    
    # Data such as b'\xff'*160
    def data_to_coeffs(self, data):
        data_len = len(data)
        if (data_len <= 310000): # for performance, keeps degree under 10,000
            chunk_size = 31
        else:
            chunk_size = (data_len // 10000) + 1
        chunks = [data[i:i+chunk_size] for i in range(0, data_len, chunk_size)]
        return [int.from_bytes(chunk, 'big') % curve_order for chunk in chunks]


    def print_data(self, data):
        print("-- First 5 lines of data ", end='')
        print("-" * 55)
        if (len(data) > 200):
            self.print_data = data[:198]
        else:
            self.print_data = data[:]
        for i in range(0, len(self.print_data), 40):
            self.print_data[i:i+32]
            print(self.print_data[i:i+40].hex(), end="")
            if (((len(self.print_data)) == len(data)) or i < 160):
                print()
            else:
                print(' ...')
        print("-" * 80)

    # --------------------------------
    # Polynomial helper methods
    # --------------------------------

    def evaluate_polynomial(self, poly, x):
        """Evaluate polynomial f(x) at x."""
        result = 0
        for coeff in reversed(poly):
            result = result * x + coeff
        return result

    # --------------------------------
    # KZG core functions
    # --------------------------------

    # SRS slow generation possible solution
    # 1) Precompute SRS
    # 2) Use Fast Exponentiation
    # 3) Parallelize SRS Generation
    # 4) Use Larger Chunk Size - less polynomial degree
    def generate_srs(self, degree, tau):
        """Generate SRS: [g^tau^0, g^tau^1, ..., g^tau^degree]"""
        return [multiply(G1, pow(tau, i, curve_order)) for i in range(degree + 1)]

    def generate_srs_fast_exponentiation(self, degree, tau): #supposed to be faster?
        powers = []
        current = 1
        for _ in range(degree + 1):
            powers.append(multiply(G1, current))
            current = (current * tau) % curve_order
        return powers

    def kzg_commit(self, coeffs, srs):
        """Commit to a polynomial: commitment = g^{f(tau)}"""
        commitment = Z1
        for i, coeff in enumerate(coeffs):
            term = multiply(srs[i], coeff % curve_order)
            commitment = add(commitment, term)
        return commitment

    def kzg_prove(self, fx, z, y, srs):
        fx_minus_y = fx[:]
        fx_minus_y[0] = (fx_minus_y[0] - y) % curve_order
        denom = [(-z) % curve_order, 1]
        output = [0] * (len(fx_minus_y) - len(denom) + 1)
        while len(fx_minus_y) >= len(denom):
            lead_coeff = fx_minus_y[-1] * pow(denom[-1], -1, curve_order) % curve_order
            deg_diff = len(fx_minus_y) - len(denom)
            output[deg_diff] = lead_coeff
            for i in range(len(denom)):
                fx_minus_y[i + deg_diff] = (fx_minus_y[i + deg_diff] - lead_coeff * denom[i]) % curve_order
            while fx_minus_y and fx_minus_y[-1] == 0:
                fx_minus_y.pop()
        if (DEBUG_OUTPUT): print("Quotient polynomial q(x):",output)
        return self.kzg_commit(output, srs)

    def kzg_verify(self, commitment, proof, z, y, g1, g2, g2_tau):
        # Compute commitment - y⋅g1
        left_expr = add(commitment, neg(multiply(g1, y % curve_order)))
        left = final_exponentiate(pairing(g2, left_expr))
        if (DEBUG_OUTPUT): print("left:", left)

        # Compute g2^{τ - z} = g2^τ ⋅ g2^{-z}
        g2_neg_z = multiply(g2, -z % curve_order)
        g2_tau_minus_z = add(g2_tau, g2_neg_z)

        # Compare e(C - y⋅g1, g2) == e(π, g2^{τ - z})
        right = final_exponentiate(pairing(g2_tau_minus_z, proof))
        if (DEBUG_OUTPUT): print("right:", right)

        return left == right

    # Multi points batch verification
    def batch_verify_same_poly(self, commitment, proofs, zs, ys, g1, g2, g2_tau):
        assert len(proofs) == len(zs) == len(ys), "Mismatched lengths"
        n = len(zs)
        # r = [random.randint(1, curve_order - 1) for _ in range(n)]
        r = [secrets.randbelow(curve_order - 1) + 1 for _ in range(n)]

        # Left pairing expression
        left_expr = Z1
        for i in range(n):
            term = add(commitment, neg(multiply(g1, ys[i])))
            left_expr = add(left_expr, multiply(term, r[i]))
        left = pairing(g2, left_expr)

        # Right pairing expression
        right = None
        for i in range(n):
            g2_tau_minus_z = add(g2_tau, multiply(g2, (-zs[i]) % curve_order))
            term = pairing(g2_tau_minus_z, multiply(proofs[i], r[i]))
            right = term if right is None else right * term

        left = final_exponentiate(left)
        right = final_exponentiate(right)

        if (DEBUG_OUTPUT): print("left: ", left)
        if (DEBUG_OUTPUT): print("right:", right)

        return left == right





