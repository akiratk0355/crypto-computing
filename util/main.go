package main

import (
	"fmt"
)

// Decompose num to bits
func IntBit(num int, i uint) byte {
	return byte((num >> i) % 2)
}

// Compute blood type compatibility from truth table
func LookupBloodTable(i int, j int) byte {
	// row=Recipient, col=Donor
	tt := [8][8]byte{
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
	return tt[i][j]
}

// Compute blood type compatibility from logical operations
/*
 Encoding    +/-   B     A
 ------------------------------
 Recipeint = x2 || x1 || x0
 Donor     = y2 || y1 || y0
*/
func ComputeBloodCompatibility(x int, y int) byte {
	x2, x1, x0 := IntBit(x, 2), IntBit(x, 1), IntBit(x, 0)
	y2, y1, y0 := IntBit(y, 2), IntBit(y, 1), IntBit(y, 0)
	return ((x2 | ((x2 ^ 1) & (y2 ^ 1))) & ((x1 & y1 & (y0 ^ 1)) | (x0 & y0 & (y1 ^ 1)) | ((y0 ^ 1) & (y1 ^ 1)) | (x0 & x1)))
}

func main() {
	// Test
	err := false
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			if ComputeBloodCompatibility(i, j) != LookupBloodTable(i, j) {
				fmt.Printf("Error at (%d,%d)\n", i, j)
				err = true
			}
		}
	}
	if !err {
		println("Success")
	}
}
