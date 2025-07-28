import random
import time
import secrets

from py_ecc.optimized_bls12_381 import (
    G1, G2,
    curve_order,
    add,
    multiply,
    normalize
)

from kzg import Kzg

if __name__ == '__main__':

    kzg = Kzg()

    # --------------------------------
    # Settings you can change
    # --------------------------------
    #     1) msg/data/fx  <- inputs message or data you want to turn into a polynomial
    #     2) tau          <- in the Setup section. any integer within the range. random in production.
    #     3) z            <- in the Proof section. any integer within the range. should not be the same as tau. random in production.
    #     4) points       <- in the Proof section. The number of points you want to verify. By default 5.

    # Real data

    import ssl, socket

    hostname  = "www.google.com"
    print("Data 1:\nRetrieving the SSL cert from:", hostname)
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
        s.connect((hostname, 443))
        der_cert = s.getpeercert(binary_form=True)  # binary format
    print("Done. Size of DER certificate:", len(der_cert), "bytes")
    kzg.print_data(der_cert)
    fx = kzg.data_to_coeffs(der_cert)

    '''
    # Chop the message in chunks of 31 character, or
    msg = "I like cats and dogs. I like cats and dogs. I like cats and dogs. I like cats and mice. I like cats and dogs. I like cats and dogs. I like cats and dogs. I like cats and mice. I like cats and dogs. I like cats and dogs. I like cats and dogs. I like cats and mice. I like cats and dogs. I like cats and dogs. I like cats and dogs. I like cats and mice. I like cats and dogs. I like cats and dogs. I like cats and dogs. I like cats and mice. I like cats and dogs. I like cats and dogs. I like cats and dogs. I like cats and mice. I like cats and dogs. I like cats and dogs. I like cats and dogs. I like cats and mice. I like cats and dogs. I like cats and dogs. I like cats and dogs. I like cats and mice. I like cats and dogs. I like cats and dogs. I like cats and dogs. I like cats and mice. I like cats and dogs."
    print(f"Message (length: {len(msg)}):",msg)
    fx = msg_to_coeffs(msg)

    # Treat every character in a message as a coeff, or
    print("Character to Polynomial")
    fx = [ord(c) for c in "A shorter message"]

    # Use binary data, or
    print("Some binary data")
    fx = data_to_coeffs(b'\xfa'*160)

    # Just hardcode an array of coeff, say, f(x) = 3 + 2x + x^2 ->
    fx = [3,2,1]
    '''

    # --------------------------------
    # Trusted Setup
    # --------------------------------
    print(f"\n-- Trusted Setup --\nfx (length: {len(fx)}): {fx}")

    # tau = random.randint(1, curve_order - 1) # or just tau = 5
    tau = secrets.randbelow(curve_order - 1) + 1
    # if (DEBUG_OUTPUT): print("tau:",tau,"(should never show this in production)")

    g1 = G1
    g2 = G2
    degree = len(fx) - 1

    # Generate SRS
    start_t1 = time.perf_counter()
    srs = kzg.generate_srs(degree, tau)
    end_t1 = time.perf_counter()
    print(f"\nOur SRS on fx {'(first 5 terms out of ' + str(degree+1) + '):' if degree >= 5 else ''}")
    for i, point in enumerate(srs[:min(5, len(srs))]): print(f"g^tau^{i} = ({normalize(point)})")
    # for i, (x, y) in enumerate(srs[:min(5,len(srs))]): print(f"g^tau^{i} = ({x}, {y})")

    g2_tau = multiply(G2, tau)
    # tau should never be used after this point
    tau = None
    print(f"\ng2_tau: {normalize(g2_tau)}\n\ntau discarded.")

    # --------------------------------
    # Generate commitment
    # --------------------------------
    start_t2 = time.perf_counter()
    commitment = kzg.kzg_commit(fx, srs)
    end_t2 = time.perf_counter()
    print("\n-- Commitment --\nC = ",normalize(commitment))

    # --------------------------------
    # Evaluate f(z) and generate proof
    # --------------------------------

    start_t3 = time.perf_counter()
    z = secrets.randbelow(curve_order - 1) + 1
    print(f"\n-- Prove --\nz's =",z)
    y = kzg.evaluate_polynomial(fx, z)
    print(f"Claim: f(z) = {y}")
    proof = kzg.kzg_prove(fx, z, y, srs)
    end_t3 = time.perf_counter()
    print(f"Proof π = {normalize(proof)}")

    # --------------------------------
    # Verify proof
    # --------------------------------
    print("\n-- Verify --")
    start_t4 = time.perf_counter()
    valid = kzg.kzg_verify(commitment, proof, z, y, g1, g2, g2_tau)
    end_t4 = time.perf_counter()
    print("KZG proof by 1 point is valid:", valid)

    # --------------------------------
    # Tamper with the message
    # --------------------------------
    print("\n-- Message tampered (one of the y's is slightly different) --")
    y2 = y
    y2 = (y2 + 1) % curve_order
    print(f"New Claim: f(z) = {y2}")
    valid = kzg.kzg_verify(commitment, proof, z, y2, g1, g2, g2_tau)
    print("KZG proof for the tampered message is valid:", valid)

    # --------------------------------
    # Benchmarking
    # --------------------------------
    print("\n-- Benchmarking --")
    print(f"SRS generation took         \t{end_t1 - start_t1:.6f} seconds")
    print(f"Commitment generation took  \t{end_t2 - start_t2:.6f} seconds")

    print(f"Proof generation took       \t{end_t3 - start_t3:.6f} seconds")
    print(f"Verification took           \t{end_t4 - start_t4:.6f} seconds")
    print(f"Total time for proof/verification:\t{end_t4 - start_t3:.6f} seconds")

    start_t6 = time.perf_counter()
    points = 5
    # zs = [random.randint(1, curve_order - 1) for _ in range(points)]
    zs = [secrets.randbelow(curve_order - 1) + 1 for _ in range(points)]
    print(f"\n-- Prove at {points} different points --\nz's =",zs)
    ys = [kzg.evaluate_polynomial(fx, z) for z in zs]
    print(f"Claim: f(z) = {ys}")
    proofs = [kzg.kzg_prove(fx, z, y, srs) for z, y in zip(zs, ys)]
    end_t6 = time.perf_counter()
    print(f"Proof π = {[normalize(p) for p in proofs]}")

    print(f"\n-- Verify {points} different points --")
    start_t5 = time.perf_counter()
    valid = kzg.batch_verify_same_poly(commitment, proofs, zs, ys, g1, g2, g2_tau)
    end_t5 = time.perf_counter()
    print(f"KZG proof by {points} points is valid:", valid)

    print(f"\nProof generation of {points} points took  \t{end_t6 - start_t6:.6f} seconds")
    print(f"Verification of {points} points took    \t{end_t5 - start_t5:.6f} seconds")
    print(f"Total time for proof/verification:\t{end_t5 - start_t6:.6f} seconds")

    print("\n--------------------------")
    print("-- Other Demonstrations --")
    print("--------------------------")
    # --------------------------------
    # Test for additive homomorphism
    # --------------------------------
    # Set tau again
    tau = random.randint(1, curve_order - 1) # or just tau = 5
    print("\n-------------------------------------------------")
    print("-- Test for Additive Homomorphism on fx and gx --")
    print("-------------------------------------------------")

    hostname1  = "github.com"
    print("\nData 1: Use previous fx on",hostname,"\nData 2:\nRetrieving the SSL cert from:", hostname1)
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname1) as s:
        s.connect((hostname1, 443))
        der_cert = s.getpeercert(binary_form=True)  # binary format
    print("Done. Size of DER certificate:", len(der_cert), "bytes")
    kzg.print_data(der_cert)
    gx = kzg.data_to_coeffs(der_cert)

    print(f"\n-- Trusted Setup --\nfx (length: {len(fx)}): {fx}\ngx (length: {len(gx)}): {gx}")

    # Pad messages to same length
    max_len = max(len(fx), len(gx))
    fx += [0] * (max_len - len(fx))
    gx += [0] * (max_len - len(gx))
    hx = [(f + g) % curve_order for f, g in zip(fx, gx)]
    print(f"\n-- Pad messages to same length --\nhx (length: {len(hx)}): {hx}")

    srs = kzg.generate_srs(max_len - 1, tau)
    cf = kzg.kzg_commit(fx, srs)
    print("\n-- Commitment --\nc_fx = ",normalize(cf))
    cg = kzg.kzg_commit(gx, srs)
    print("c_gx = ",normalize(cg))
    ch = kzg.kzg_commit(hx, srs)
    print("c_hx = ",normalize(ch))

    print("\nCheck add(c_fx, c_gx) == c_hx ...")
    assert normalize(add(cf, cg)) == normalize(ch)
    print("It's homomorphic!")

    # --------------------------------
    # Show case of large degree SRS generation
    # --------------------------------
    print("\n----------------------------------------------")
    print("-- Test for SRS generation on higher degree --")
    print("----------------------------------------------")

    import requests
    from PIL import Image
    from io import BytesIO
    url = "https://www.unsw.edu.au/content/dam/images/graphics/logos/unsw/unsw_0.png"
    print("\nData 2:\nDownloading image from:", url)
    response = requests.get(url)
    response.raise_for_status()
    img = Image.open(BytesIO(response.content)).convert("L")  # "L" = grayscale
    fx = list(img.getdata())
    print(f"Image size {img.size} = {len(fx)} bytes")
    print("fx first 50 coeffs",fx[:50])

    print(f"\n-- Generate SRS (degree: {len(fx) - 1}) --")
    # start_t7 = time.perf_counter()
    # srs = generate_srs(len(fx) - 1, tau)
    # end_t7 = time.perf_counter()
    # print(f"Done. It took {end_t7 - start_t7:.6f} seconds")
    print("Code remarked. \n\nA 46199 degree srs generation took 570.47 seconds in the testing environment.")
    print("Suggest solution: use a trusted SRS source such as https://trusted-setup-ceremony.s3.amazonaws.com/kzg-ceremony-2022-08-08.tar.gz.")