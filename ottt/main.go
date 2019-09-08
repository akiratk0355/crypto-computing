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
func IntBit(num int, i uint) byte {
	return byte((num >> i) % 2)
}

// Blood type table
// row=Recipient, col=Donor
var tt = [8][8]uint64{
	// O- A- B- AB- O+ A+ B+ AB+
	{1, 0, 0, 0, 0, 0, 0, 0}, // O-
	{1, 1, 0, 0, 0, 0, 0, 0}, // A-
	{1, 0, 1, 0, 0, 0, 0, 0}, // B-
	{1, 1, 1, 1, 0, 0, 0, 0}, // AB-
	{1, 0, 0, 0, 1, 0, 0, 0}, // O+
	{1, 1, 0, 0, 1, 1, 0, 0}, // A+
	{1, 0, 1, 0, 1, 0, 1, 0}, // B+
	{1, 1, 1, 1, 1, 1, 1, 1}, // AB+
}

// Compute blood type compatibility from truth table
func LookupBloodTable(i uint64, j uint64) uint64 {
	return tt[i][j]
}

// Dealer class
type Dealer struct {
	n      uint64
	r, s   uint64
	Ma, Mb [][]uint64
}

func (d *Dealer) Init(secpar uint64) {
	d.n = secpar
	msize := uint64(1 << d.n)

	// We use cryptographically secure PRNG
	rtmp, _ := rand.Int(rand.Reader, big.NewInt(int64(msize)))
	stmp, _ := rand.Int(rand.Reader, big.NewInt(int64(msize)))
	d.r = rtmp.Uint64()
	d.s = stmp.Uint64()
	for i := uint64(0); i < msize; i++ {
		var Matmp, Mbtmp []uint64
		for j := uint64(0); j < msize; j++ {
			t1, _ := rand.Int(rand.Reader, big.NewInt(2))
			t2 := LookupBloodTable((uint64(i)-d.r+msize)%msize, (uint64(j)-d.s+msize)%msize)
			Matmp = append(Matmp, t1.Uint64()^t2)
			Mbtmp = append(Mbtmp, t1.Uint64())
		}
		d.Ma = append(d.Ma, Matmp)
		d.Mb = append(d.Mb, Mbtmp)
	}
}

func (d *Dealer) RandA() (uint64, [][]uint64) {
	return d.r, d.Ma
}

func (d *Dealer) RandB() (uint64, [][]uint64) {
	return d.s, d.Mb
}

// Alice class
type Alice struct {
	n, x, r, u, v, zb uint64
	M                 [][]uint64
}

func (a *Alice) Init(secpar uint64, input uint64, mask uint64, table [][]uint64) {
	a.n = secpar
	a.x = input
	a.r = mask
	a.M = table
}

func (a *Alice) Send() uint64 {
	a.u = (a.x + a.r) % (1 << a.n)
	return a.u
}

func (a *Alice) Receive(data [2]uint64) {
	a.v = data[0]
	a.zb = data[1]
}

func (a *Alice) Output() uint64 {
	return (a.M[a.u][a.v] ^ a.zb)
}

// Bob class
type Bob struct {
	n, y, s, u, v uint64
	M             [][]uint64
}

func (b *Bob) Init(secpar uint64, input uint64, mask uint64, table [][]uint64) {
	b.n = secpar
	b.y = input
	b.s = mask
	b.M = table
}

func (b *Bob) Receive(u uint64) {
	b.u = u
}

func (b *Bob) Send() [2]uint64 {
	b.v = (b.y + b.s) % (1 << b.n)
	return [2]uint64{b.v, b.M[b.u][b.v]}
}

func main() {
	var secpar uint64 = 3
	// Read parties' input from command line arguments
	x, _ := strconv.ParseUint(os.Args[1], 10, 64)
	y, _ := strconv.ParseUint(os.Args[2], 10, 64)

	// Initialize parties
	d := Dealer{}
	a := Alice{}
	b := Bob{}
	d.Init(secpar)
	r, Ma := d.RandA()
	s, Mb := d.RandB()
	fmt.Println("Alice received randomness", r)
	//fmt.Println("Alice received table", Ma)
	fmt.Println("Bob received randomness", s)
	//fmt.Println("Bob received table", Mb)
	a.Init(secpar, x, r, Ma)
	b.Init(secpar, y, s, Mb)

	// Run the protocol
	b.Receive(a.Send())
	a.Receive(b.Send())
	z := a.Output()
	fmt.Printf("Securely computed f(%v,%v)=%v\n", x, y, z)

	// Correctness check
	if z != LookupBloodTable(x, y) {
		println("Error")
	} else {
		println("Success")
	}
}
