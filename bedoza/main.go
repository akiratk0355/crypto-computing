// usage: go run main.go <Party's input> <Bob's input>
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

func (A *Party) Input(input int) (int, int, int) {
	x2, x1, x0 := IntBit(input, 2), IntBit(input, 1), IntBit(input, 0)
	x2bt, _ := rand.Int(rand.Reader, big.NewInt(2))
	x2b := int(x2bt.Int64())
	x1bt, _ := rand.Int(rand.Reader, big.NewInt(2))
	x1b := int(x1bt.Int64())
	x0bt, _ := rand.Int(rand.Reader, big.NewInt(2))
	x0b := int(x0bt.Int64())
	if !A.isBob {
		A.x2 = x2 ^ x2b
		A.x1 = x1 ^ x1b
		A.x0 = x0 ^ x0b
	} else {
		A.y2 = x2 ^ x2b
		A.y1 = x1 ^ x1b
		A.y0 = x0 ^ x0b
	}
	return x2b, x1b, x0b
}

func (A *Party) ReceiveInput(input2 int, input1 int, input0 int) {
	if !A.isBob {
		A.y2 = input2
		A.y1 = input1
		A.y0 = input0
	} else {
		A.x2 = input2
		A.x1 = input1
		A.x0 = input0
	}
}

func (A *Party) Phase1() (int, int, int, int, int, int) {
	// Compute zi = (xi ^ 1)
	A.z0 = A.x0
	A.z1 = A.x1
	A.z2 = A.x2
	if !A.isBob {
		A.z0 = A.z0 ^ 1
		A.z1 = A.z1 ^ 1
		A.z2 = A.z2 ^ 1
	}
	// Compute z0 & y0
	A.T0, A.triples = A.triples[0], A.triples[1:]
	A.d0 = A.z0 ^ A.T0.u
	A.e0 = A.y0 ^ A.T0.v

	// Compute z1 & y1
	A.T1, A.triples = A.triples[0], A.triples[1:]
	A.d1 = A.z1 ^ A.T1.u
	A.e1 = A.y1 ^ A.T1.v

	// Compute z2 & y2
	A.T2, A.triples = A.triples[0], A.triples[1:]
	A.d2 = A.z2 ^ A.T2.u
	A.e2 = A.y2 ^ A.T2.v

	return A.d0, A.e0, A.d1, A.e1, A.d2, A.e2
}

func (A *Party) Phase2(Bd0 int, Be0 int, Bd1 int, Be1 int, Bd2 int, Be2 int) (int, int) {
	// Finalize zi & yi
	A.d0 = A.d0 ^ Bd0
	A.d1 = A.d1 ^ Bd1
	A.d2 = A.d2 ^ Bd2
	A.e0 = A.e0 ^ Be0
	A.e1 = A.e1 ^ Be1
	A.e2 = A.e2 ^ Be2

	A.z0 = A.T0.w ^ (A.e0 & A.T0.u) ^ (A.d0 & A.T0.v)
	A.z1 = A.T1.w ^ (A.e1 & A.T1.u) ^ (A.d1 & A.T1.v)
	A.z2 = A.T2.w ^ (A.e2 & A.T2.u) ^ (A.d2 & A.T2.v)

	if !A.isBob {
		A.z0 = A.z0 ^ (A.d0 & A.e0)
		A.z1 = A.z1 ^ (A.d1 & A.e1)
		A.z2 = A.z2 ^ (A.d2 & A.e2)
	}

	// Compute zi ^ 1
	if !A.isBob {
		A.z0 = A.z0 ^ 1
		A.z1 = A.z1 ^ 1
		A.z2 = A.z2 ^ 1
	}

	// Compute z0 & z1
	A.T0, A.triples = A.triples[0], A.triples[1:]
	A.d0 = A.z0 ^ A.T0.u
	A.e0 = A.z1 ^ A.T0.v

	return A.d0, A.e0
}

func (A *Party) Phase3(Bd0 int, Be0 int) (int, int) {
	// Finalize z0 & z1
	A.d0 = A.d0 ^ Bd0
	A.e0 = A.e0 ^ Be0
	A.z0 = A.T0.w ^ (A.e0 & A.T0.u) ^ (A.d0 & A.T0.v)
	if !A.isBob {
		A.z0 = A.z0 ^ (A.d0 & A.e0)
	}

	// Compute z0 & z2
	A.T0, A.triples = A.triples[0], A.triples[1:]
	A.d0 = A.z0 ^ A.T0.u
	A.e0 = A.z2 ^ A.T0.v

	return A.d0, A.e0
}

func (A *Party) Phase4(Bd0 int, Be0 int) int {
	// Finalize z0 & z2
	A.d0 = A.d0 ^ Bd0
	A.e0 = A.e0 ^ Be0
	A.z0 = A.T0.w ^ (A.e0 & A.T0.u) ^ (A.d0 & A.T0.v)
	if !A.isBob {
		A.z0 = A.z0 ^ (A.d0 & A.e0)
	}
	return A.z0
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
