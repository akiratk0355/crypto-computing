// usage: go run main.go <Alice's input> <Bob's input>
package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strconv"
)

// Decompose num to bits
func IntBit(num int, i uint) int {
	return (num >> i) % 2
}

// Compute blood type compatibility from logical operations
/*
 Encoding    +/-   B     A
 ------------------------------
 Recipeint = x2 || x1 || x0
 Donor     = y2 || y1 || y0
*/
func ComputeBloodCompatibility(x int, y int) int {
	x2, x1, x0 := IntBit(x, 2), IntBit(x, 1), IntBit(x, 0)
	y2, y1, y0 := IntBit(y, 2), IntBit(y, 1), IntBit(y, 0)
	return (1 ^ (y0 & (1 ^ x0))) & (1 ^ (y1 & (1 ^ x1))) & (1 ^ (y2 & (1 ^ x2)))
}

type Triple struct {
	u, v, w int
}

// Dealer class
type Dealer struct {
	numand   int
	atriples []Triple
	btriples []Triple
}

func (D *Dealer) Init(n int) {
	D.numand = n
	// We use cryptographically secure PRNG
	for i := 0; i < n; i++ {
		uat, _ := rand.Int(rand.Reader, big.NewInt(2))
		ua := int(uat.Int64())
		ubt, _ := rand.Int(rand.Reader, big.NewInt(2))
		ub := int(ubt.Int64())
		vat, _ := rand.Int(rand.Reader, big.NewInt(2))
		va := int(vat.Int64())
		vbt, _ := rand.Int(rand.Reader, big.NewInt(2))
		vb := int(vbt.Int64())
		wat, _ := rand.Int(rand.Reader, big.NewInt(2))
		wa := int(wat.Int64())
		wb := ((ua ^ ub) & (va ^ vb)) ^ wa
		D.atriples = append(D.atriples, Triple{ua, va, wa})
		D.btriples = append(D.btriples, Triple{ub, vb, wb})
	}
}

func (D *Dealer) RandA() []Triple {
	return D.atriples
}

func (D *Dealer) RandB() []Triple {
	return D.btriples
}

// Party class
type Party struct {
	x0, x1, x2 int
	y0, y1, y2 int
	z0, z1, z2 int
	d0, d1, d2 int
	e0, e1, e2 int
	T0, T1, T2 Triple
	triples    []Triple
	isBob      bool
}

func (P *Party) Init(triples []Triple, bob bool) {
	P.triples = triples
	P.isBob = bob
}

func (P *Party) Input(input int) (int, int, int) {
	x2, x1, x0 := IntBit(input, 2), IntBit(input, 1), IntBit(input, 0)
	x2bt, _ := rand.Int(rand.Reader, big.NewInt(2))
	x2b := int(x2bt.Int64())
	x1bt, _ := rand.Int(rand.Reader, big.NewInt(2))
	x1b := int(x1bt.Int64())
	x0bt, _ := rand.Int(rand.Reader, big.NewInt(2))
	x0b := int(x0bt.Int64())
	if !P.isBob {
		P.x2 = x2 ^ x2b
		P.x1 = x1 ^ x1b
		P.x0 = x0 ^ x0b
	} else {
		P.y2 = x2 ^ x2b
		P.y1 = x1 ^ x1b
		P.y0 = x0 ^ x0b
	}
	return x2b, x1b, x0b
}

func (P *Party) ReceiveInput(input2 int, input1 int, input0 int) {
	if !P.isBob {
		P.y2 = input2
		P.y1 = input1
		P.y0 = input0
	} else {
		P.x2 = input2
		P.x1 = input1
		P.x0 = input0
	}
}

func (P *Party) Phase1() (int, int, int, int, int, int) {
	// Compute zi = (xi ^ 1)
	P.z0 = P.x0
	P.z1 = P.x1
	P.z2 = P.x2
	if !P.isBob {
		P.z0 = P.z0 ^ 1
		P.z1 = P.z1 ^ 1
		P.z2 = P.z2 ^ 1
	}
	// Compute z0 & y0
	P.T0, P.triples = P.triples[0], P.triples[1:]
	P.d0 = P.z0 ^ P.T0.u
	P.e0 = P.y0 ^ P.T0.v

	// Compute z1 & y1
	P.T1, P.triples = P.triples[0], P.triples[1:]
	P.d1 = P.z1 ^ P.T1.u
	P.e1 = P.y1 ^ P.T1.v

	// Compute z2 & y2
	P.T2, P.triples = P.triples[0], P.triples[1:]
	P.d2 = P.z2 ^ P.T2.u
	P.e2 = P.y2 ^ P.T2.v

	return P.d0, P.e0, P.d1, P.e1, P.d2, P.e2
}

func (P *Party) Phase2(Bd0 int, Be0 int, Bd1 int, Be1 int, Bd2 int, Be2 int) (int, int) {
	// Finalize zi & yi
	P.d0 = P.d0 ^ Bd0
	P.d1 = P.d1 ^ Bd1
	P.d2 = P.d2 ^ Bd2
	P.e0 = P.e0 ^ Be0
	P.e1 = P.e1 ^ Be1
	P.e2 = P.e2 ^ Be2

	P.z0 = P.T0.w ^ (P.e0 & P.T0.u) ^ (P.d0 & P.T0.v)
	P.z1 = P.T1.w ^ (P.e1 & P.T1.u) ^ (P.d1 & P.T1.v)
	P.z2 = P.T2.w ^ (P.e2 & P.T2.u) ^ (P.d2 & P.T2.v)

	if !P.isBob {
		P.z0 = P.z0 ^ (P.d0 & P.e0)
		P.z1 = P.z1 ^ (P.d1 & P.e1)
		P.z2 = P.z2 ^ (P.d2 & P.e2)
	}

	// Compute zi ^ 1
	if !P.isBob {
		P.z0 = P.z0 ^ 1
		P.z1 = P.z1 ^ 1
		P.z2 = P.z2 ^ 1
	}

	// Compute z0 & z1
	P.T0, P.triples = P.triples[0], P.triples[1:]
	P.d0 = P.z0 ^ P.T0.u
	P.e0 = P.z1 ^ P.T0.v

	return P.d0, P.e0
}

func (P *Party) Phase3(Bd0 int, Be0 int) (int, int) {
	// Finalize z0 & z1
	P.d0 = P.d0 ^ Bd0
	P.e0 = P.e0 ^ Be0
	P.z0 = P.T0.w ^ (P.e0 & P.T0.u) ^ (P.d0 & P.T0.v)
	if !P.isBob {
		P.z0 = P.z0 ^ (P.d0 & P.e0)
	}

	// Compute z0 & z2
	P.T0, P.triples = P.triples[0], P.triples[1:]
	P.d0 = P.z0 ^ P.T0.u
	P.e0 = P.z2 ^ P.T0.v

	return P.d0, P.e0
}

func (P *Party) Phase4(Bd0 int, Be0 int) int {
	// Finalize z0 & z2
	P.d0 = P.d0 ^ Bd0
	P.e0 = P.e0 ^ Be0
	P.z0 = P.T0.w ^ (P.e0 & P.T0.u) ^ (P.d0 & P.T0.v)
	if !P.isBob {
		P.z0 = P.z0 ^ (P.d0 & P.e0)
	}
	return P.z0
}

func main() {
	n := 5
	// Read parties' input from command line arguments
	x, _ := strconv.ParseInt(os.Args[1], 10, 64)
	y, _ := strconv.ParseInt(os.Args[2], 10, 64)

	// Initialize parties
	D := Dealer{}
	A := Party{}
	B := Party{}
	D.Init(n)
	tripa := D.RandA()
	tripb := D.RandB()
	A.Init(tripa, false)
	B.Init(tripb, true)
	println("Parties initialized")

	B.ReceiveInput(A.Input(int(x)))
	A.ReceiveInput(B.Input(int(y)))
	println("Input phase done")

	dA0, eA0, dA1, eA1, dA2, eA2 := A.Phase1()
	dB0, eB0, dB1, eB1, dB2, eB2 := B.Phase1()
	println("Phase1 done")

	dAp2, eAp2 := A.Phase2(dB0, eB0, dB1, eB1, dB2, eB2)
	dBp2, eBp2 := B.Phase2(dA0, eA0, dA1, eA1, dA2, eA2)
	println("Phase2 done")

	dAp3, eAp3 := A.Phase3(dBp2, eBp2)
	dBp3, eBp3 := B.Phase3(dAp2, eAp2)
	println("Phase3 done")

	outA := A.Phase4(dBp3, eBp3)
	outB := B.Phase4(dAp3, eAp3)
	println("Phase4 done")

	z := outA ^ outB
	fmt.Printf("Securely computed f(%v,%v)=%v\n", int(x), int(y), z)

	// Correctness check
	if z != ComputeBloodCompatibility(int(x), int(y)) {
		println("Error")
	} else {
		println("Success")
	}
}
