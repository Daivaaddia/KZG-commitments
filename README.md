# About This Project

This project explores optimizations of the KZG commitment scheme in Python, with the goal of reducing the runtime of any of the four core stages: **setup**, **commit**, **prove**, and **verify**. The work is intended for **educational purposes**.

In this repository, there are two parts:
  * The KZG commitment implementation and optimisation
    * `KZG_commitments_main.ipynb`
     
  * The KZG vs Merkle Tree Benchmark
    * `kzg.py`
    * `kzgUsage.py`
    * `merkleTree.py`
    * `benchmarking.py`

---

# The KZG commitment implementation and optimisation

## How to Read the Jupyter Notebook file

You can view `KZG_commitments_main.ipynb` directly on GitHub, as GitHub supports rendering of Jupyter Notebook files. However, it is designed to be run in **Google Colab** for the best experience.

### To load the notebook:

1. Download `KZG_commitments_main.ipynb` from this repository.
2. Open the file in one of the following:
   - **Google Colab**: using a Google account, an internet connection, and a web browser.
   - **Jupyter Notebook**: with the appropriate Python environment.

## How to Run This Notebook

1. **You don’t have to run it.**
   - All code cells and outputs are already provided.
   - You can simply read the notebook and examine the results.

2. **However, you may run or modify it if you wish.**
   - Use Google Colab (recommended) or a Jupyter environment (e.g. Jypyter Notebook, VSCode w/ Jypyter and Python extension, or others) with **Python 3.11** (the version used during development).
   - It may also work with other Python versions, but this has not been tested.

     > **Note:** The `py_ecc.bls12_381.pairing` module is known to have issues with **Python 3.11 on Windows**, which may cause kernel crashes.

   - Ensure the `py_ecc` library is installed/installable in your environment. The notebook will not run without it.

3. **To begin:**
   - Search for the string `"Fast_Mode"` and set it to `1`.
     - This enables a faster demonstration mode.
   - Search for the section labeled **“Tunable Variables”**.
     - You’ll find a cell containing adjustable parameters.
     - Modify these as needed.
   - Then either:
     - Run all cells (`Runtime > Run all` in Colab), or
     - Run cells one by one in order.

   > Note: The full version (with `Fast_Mode = 0`) uses a **3991-degree polynomial**, which takes ~45 minutes for the baseline setup and ~4 hours for the full notebook.
   > 
   > Setting `Fast_Mode = 1` reduces the maximum degree to 400 and the number of test inputs to 4, along with a few other changes, reducing runtime from hours down to minutes.

## File Overview

### Components

This notebook showcases multiple KZG commitment implementations, performance benchmarks, and optimization techniques. It includes the following sections:

> For a detailed discussion and analysis, please refer to the project report (not included in this repository).

- **Library Installation & Import**
  - Setup of required dependencies.

- **Utility Functions**
  - Helper methods for commitment, timing, and verification.

- **Global Variables**
  - Real data conversion to polynomials, number of proofs, and tunable parameters.

- **KZG Implementations**
  - Using [`py_ecc.bls12_381`](https://github.com/ethereum/py_ecc) — the standard affine-coordinate version.
  - Using [`py_ecc.optimized_bls12_381`](https://github.com/ethereum/py_ecc) — a faster version using projective coordinates and Cython.
  - A modified version of [`kzg-python-toy`](https://github.com/kassandraoftroy/kzg-python-toy).

- **Implementation Showcases**
  - Comparison of the three KZG libraries:
    - Setup time
    - Commitment time
    - Proof/witness generation
    - Proof verification

- **Optimization Benchmarks**
  - **Multi-Point Batch Verification**
    - Prove and verify 25 points using batching techniques.
  - **Additive Homomorphism**
    - Combine 8 commitments into a single proof/verification using KZG’s homomorphic properties.
  - **Trusted Setup (Trusted SRS)**
    - Use a pre-generated SRS (up to degree 4095) instead of generating one on the fly.
  - **Combined Optimizations**
    - Apply all optimizations for best overall performance.
  - **Final Summary**

## Possible Improvements (Left Out in Final Version)

- **Pre-generated & Cached SRS**  
  For simplicity and speed, we limited polynomial degrees to ≤4000, aligning with the KZG Trusted Setup constraints, which provides an SRS only up to degree 4095. While the system can handle higher degrees using self-generated SRS, this can significantly degrade performance.

- **Consistent Use of τ and Evaluation Points**  
  For security, we used Python’s `secrets` module instead of the standard `random` module. We also used different τ values and distinct sets of evaluation points for each test case. While this adds variability and affects benchmarking consistency, it reflects realistic and reproducible conditions.

- **Limitations of Batch Opening with Our SRS**  
  We considered implementing the batch opening optimization from the original KZG paper. However, this requires SRS elements of the form g2^{tau^d}, which are not available in our current SRS setup. Supporting this would introduce significant complexity and is therefore deferred.

---

# The KZG vs Merkle Tree Benchmark

The set of code we used for benchmarking the KZG and Merkle Tree.

---

## Acknowledgements & References

- **KZG Commitment Scheme**  
  *Constant-Size Commitments to Polynomials and Their Applications*  
  *Aniket Kate, Gregory M. Zaverucha, Ian Goldberg*  
  https://iacr.org/archive/asiacrypt2010/6477178/6477178.pdf

- **Building Trust with KZG Commitment: Understanding, Implementation, and Python Code Samples**
  https://medium.com/cumberlandlabs/building-trust-with-kzg-commitment-understanding-implementation-and-python-code-samples-c73075d941e6

- **Zero-Knowledge Proofs: KZG Polynomial Commitment and Verification**
  https://medium.com/@abhiveerhome/zero-knowledge-proofs-kzg-polynomial-commitment-and-verification-5a82d62fdefd

- **py_ecc** — Ethereum Foundation's elliptic curve library  
  https://github.com/ethereum/py_ecc/

- **kzg-python-toy** — A reference implementation by *Kassandra of Troy*  
  https://github.com/kassandraoftroy/kzg-python-toy/

- **Public Trusted SRS** — From the Ethereum KZG Ceremony  
  https://ceremony.ethereum.org/#/record
