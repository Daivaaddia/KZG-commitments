import os
import secrets
import random
import time
import json
import matplotlib.pyplot as plt
import numpy as np
import string

from py_ecc.optimized_bls12_381 import (
    G1, G2,
    curve_order,
    multiply,
)

from kzg import Kzg
from merkleTree import MerkleTree

results = {}
BENCHMARK_SIZES = [1 << 10, 1 << 11, 1 << 12, 1 << 13, 1 << 14]

def benchmark(size):
    print(f"Testing size {size}")
    dataArray = [(''.join(random.choices(string.ascii_letters + string.digits, k=31))) for _ in range(size)]
    data = ''.join(dataArray).encode('utf-8')

    merkleTree = MerkleTree()
    merkleTree.makeTreeFromArray(dataArray.copy())

    start = time.time()
    merkleTree.calculateMerkleRoot()
    merkle_time = time.time() - start

    index = random.randint(0, len(dataArray))
    start = time.time()
    proof = merkleTree.getProof(dataArray[index])
    assert(proof != None)
    merkle_proof_time = time.time() - start

    start = time.time()
    assert merkleTree.verifyUtil(dataArray)
    merkle_verify_time = time.time() - start
    
    fx = kzg.data_to_coeffs(data)
    tau = secrets.randbelow(curve_order - 1) + 1

    g1 = G1
    g2 = G2
    degree = len(fx) - 1

    srs = kzg.generate_srs(degree, tau)
    g2_tau = multiply(G2, tau)

    tau = None

    start = time.time()
    commitment = kzg.kzg_commit(fx, srs)
    kzg_time = time.time() - start

    z = secrets.randbelow(curve_order - 1) + 1
    start = time.time()
    y = kzg.evaluate_polynomial(fx, z)
    proof = kzg.kzg_prove(fx, z, y, srs)
    kzg_proof_time = time.time() - start

    start = time.time()
    valid = kzg.kzg_verify(commitment, proof, z, y, g1, g2, g2_tau)
    assert(valid)
    kzg_verify_time = time.time() - start

    results["size"].append(size)
    results["merkle_commit"].append(merkle_time)
    results["merkle_prove"].append(merkle_proof_time)
    results["merkle_verify"].append(merkle_verify_time)
    results["kzg_commit"].append(kzg_time)
    results["kzg_prove"].append(kzg_proof_time)
    results["kzg_verify"].append(kzg_verify_time)

if __name__ == '__main__':
    kzg = Kzg()
    merkleTree = MerkleTree()

    with open("srsSmall.json", "r") as f:
        file = json.load(f)
    
    results["size"] = []
    results["merkle_commit"] = []
    results["merkle_prove"] = []
    results["merkle_verify"] = []
    results["kzg_commit"] = []
    results["kzg_prove"] = []
    results["kzg_verify"] = []

    for size in BENCHMARK_SIZES:
        benchmark(size)

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3)
    xAxis = np.array(results["size"])

    ax1.plot(xAxis, np.array(results["merkle_commit"]), 'x', linestyle='-', label="Merkle Commit")
    ax1.plot(xAxis, np.array(results["kzg_commit"]), 'o', label="KZG Commit")
    ax1.set_xlabel("Number of elements")
    ax1.set_ylabel("Time")
    ax1.set_title("Commitment Time vs Input Size")
    ax1.legend()
    ax1.grid(True)

    ax2.plot(xAxis, np.array(results["merkle_prove"]), 'x', linestyle='-', label="Merkle Proof")
    ax2.plot(xAxis, np.array(results["kzg_prove"]), 'o', label="KZG Proof")
    ax2.set_xlabel("Number of elements")
    ax2.set_ylabel("Time")
    ax2.set_title("Proving Time vs Input Size")
    ax2.legend()
    ax2.grid(True)

    ax3.plot(xAxis, np.array(results["merkle_verify"]), 'x', linestyle='-', label="Merkle verify")
    ax3.plot(xAxis, np.array(results["kzg_verify"]), 'o', label="KZG verify")
    ax3.set_xlabel("Number of elements")
    ax3.set_ylabel("Time")
    ax3.set_title("Verification Time vs Input Size")
    ax3.legend()
    ax3.grid(True)

    plt.tight_layout()
    plt.show()





