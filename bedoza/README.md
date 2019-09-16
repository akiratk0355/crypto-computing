# BeDOZa  protocol with passive security
Securely computes the blood type compatibility between Alice and Bob with [BeDOZa protocol](http://eprint.iacr.org/2010/514).
The function `ComputeBloodCompatibility` contains a circuit to be computed, which has 5 AND gates.
Note that the first three AND gates in the circuit are computed in parallel so that we require only 3 interactions in total.

### Usage
```
go run main.go  <Alice's input x\in[0,7]> <Bob's input y\in[0,7]>
```

