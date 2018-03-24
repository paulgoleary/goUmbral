# goUmbral

This is a POC implementation of the Umbral threshold proxy re-encryption scheme: https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf

This work is based on NuCypher's reference implementation, and care (with some testing) has been taken to validate compatibility: https://github.com/nucypher/pyUmbral

At this point only the 'round-trip' basic path of encapsulation, direct decapsulation and split-re-encryption key decapsulation have been implemented.
This is demonstrated in the `umbral/simple_api_test.go` test, which parallels a similar test in pyUmbral.

Some random thoughts and notes:
* Many corners have been cut relative to the reference implementation - for example, only the default `SECP256K1` curve is currently implemented.
* Oddly, Go does not currently seem to implement a general enough elliptic curve to represent `SECP256K1`.
The available Go library - https://golang.org/pkg/crypto/elliptic/ - implements only a set of standard curves with fixed `a=-3`.
I assume this is to take advantage of performance optimizations.
* In any case, I borrowed a more general implementation of a Weierstrass curve from another project I've worked on.
That implementation has been tested for correctness and compatibility with the PBC pairing-based crypto library (https://crypto.stanford.edu/pbc/.) but should likely also be considered POC-level code.
If anyone knows of a more, complete general implementation in Go it may make sense to use that instead.
* One positive result of this initial work is to demonstrate that a compatible implementation of Umbral is fairly straightforward to achieve on other platforms and languages, particularly Go.
This speaks to good implementation and design choices by NuCypher. It will be interesting to see if this proves to be the case on other platforms, however - I'm currently thinking about Rust, for example.
* Comments, questions, critiques are welcome and encouraged.

