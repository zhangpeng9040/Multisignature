// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdsa

import (
	"bufio"
	"compress/bzip2"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
	"fmt"
)

func testKeyGeneration(t *testing.T, c elliptic.Curve, tag string) {
	priv, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Errorf("%s: error: %s", tag, err)
		return
	}
	if !c.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("%s: public key invalid: %s", tag, err)
	}
}

func TestKeyGeneration(t *testing.T) {
	testKeyGeneration(t, elliptic.P224(), "p224")
	if testing.Short() {
		return
	}
	testKeyGeneration(t, elliptic.P256(), "p256")
	testKeyGeneration(t, elliptic.P384(), "p384")
	testKeyGeneration(t, elliptic.P521(), "p521")
}

func BenchmarkSignP256(b *testing.B) {
	b.ResetTimer()
	p256 := elliptic.P256()
	hashed := []byte("testing")
	priv, _ := GenerateKey(p256, rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Sign(rand.Reader, priv, hashed)
	}
}

func BenchmarkSignP384(b *testing.B) {
	b.ResetTimer()
	p384 := elliptic.P384()
	hashed := []byte("testing")
	priv, _ := GenerateKey(p384, rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Sign(rand.Reader, priv, hashed)
	}
}

func BenchmarkVerifyP256(b *testing.B) {
	b.ResetTimer()
	p256 := elliptic.P256()
	hashed := []byte("testing")
	priv, _ := GenerateKey(p256, rand.Reader)
	r, s, _ := Sign(rand.Reader, priv, hashed)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(&priv.PublicKey, hashed, r, s)
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	b.ResetTimer()
	p256 := elliptic.P256()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateKey(p256, rand.Reader)
	}
}

func testSignAndVerify(t *testing.T, c elliptic.Curve, tag string) {
	priv, _ := GenerateKey(c, rand.Reader)

	hashed := []byte("testing")
	r, s, err := Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf("%s: error signing: %s", tag, err)
		return
	}

	if !Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("%s: Verify failed", tag)
	}

	hashed[0] ^= 0xff
	if Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("%s: Verify always works!", tag)
	}
}

func TestSignAndVerify(t *testing.T) {
	testSignAndVerify(t, elliptic.P224(), "p224")
	if testing.Short() {
		return
	}
	testSignAndVerify(t, elliptic.P256(), "p256")
	testSignAndVerify(t, elliptic.P384(), "p384")
	testSignAndVerify(t, elliptic.P521(), "p521")
}

func TestSignAndVerifyIndividual(t *testing.T) {
	for i := 0; i <16384; i++{
		testSignAndVerify(t, elliptic.P256(), "p256")
	}
}

func testNonceSafety(t *testing.T, c elliptic.Curve, tag string) {
	priv, _ := GenerateKey(c, rand.Reader)

	hashed := []byte("testing")
	r0, s0, err := Sign(zeroReader, priv, hashed)
	if err != nil {
		t.Errorf("%s: error signing: %s", tag, err)
		return
	}

	hashed = []byte("testing...")
	r1, s1, err := Sign(zeroReader, priv, hashed)
	if err != nil {
		t.Errorf("%s: error signing: %s", tag, err)
		return
	}

	if s0.Cmp(s1) == 0 {
		// This should never happen.
		t.Errorf("%s: the signatures on two different messages were the same", tag)
	}

	if r0.Cmp(r1) == 0 {
		t.Errorf("%s: the nonce used for two different messages was the same", tag)
	}
}

func TestNonceSafety(t *testing.T) {
	testNonceSafety(t, elliptic.P224(), "p224")
	if testing.Short() {
		return
	}
	testNonceSafety(t, elliptic.P256(), "p256")
	testNonceSafety(t, elliptic.P384(), "p384")
	testNonceSafety(t, elliptic.P521(), "p521")
}

func testINDCCA(t *testing.T, c elliptic.Curve, tag string) {
	priv, _ := GenerateKey(c, rand.Reader)

	hashed := []byte("testing")
	r0, s0, err := Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf("%s: error signing: %s", tag, err)
		return
	}

	r1, s1, err := Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf("%s: error signing: %s", tag, err)
		return
	}

	if s0.Cmp(s1) == 0 {
		t.Errorf("%s: two signatures of the same message produced the same result", tag)
	}

	if r0.Cmp(r1) == 0 {
		t.Errorf("%s: two signatures of the same message produced the same nonce", tag)
	}
}

func TestINDCCA(t *testing.T) {
	testINDCCA(t, elliptic.P224(), "p224")
	if testing.Short() {
		return
	}
	testINDCCA(t, elliptic.P256(), "p256")
	testINDCCA(t, elliptic.P384(), "p384")
	testINDCCA(t, elliptic.P521(), "p521")
}

func fromHex(s string) *big.Int {
	r, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex")
	}
	return r
}

func TestVectors(t *testing.T) {
	// This test runs the full set of NIST test vectors from
	// http://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3ecdsatestvectors.zip
	//
	// The SigVer.rsp file has been edited to remove test vectors for
	// unsupported algorithms and has been compressed.

	if testing.Short() {
		return
	}

	f, err := os.Open("testdata/SigVer.rsp.bz2")
	if err != nil {
		t.Fatal(err)
	}

	buf := bufio.NewReader(bzip2.NewReader(f))

	lineNo := 1
	var h hash.Hash
	var msg []byte
	var hashed []byte
	var r, s *big.Int
	pub := new(PublicKey)

	for {
		line, err := buf.ReadString('\n')
		if len(line) == 0 {
			if err == io.EOF {
				break
			}
			t.Fatalf("error reading from input: %s", err)
		}
		lineNo++
		// Need to remove \r\n from the end of the line.
		if !strings.HasSuffix(line, "\r\n") {
			t.Fatalf("bad line ending (expected \\r\\n) on line %d", lineNo)
		}
		line = line[:len(line)-2]

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		if line[0] == '[' {
			line = line[1 : len(line)-1]
			parts := strings.SplitN(line, ",", 2)

			switch parts[0] {
			case "P-224":
				pub.Curve = elliptic.P224()
			case "P-256":
				pub.Curve = elliptic.P256()
			case "P-384":
				pub.Curve = elliptic.P384()
			case "P-521":
				pub.Curve = elliptic.P521()
			default:
				pub.Curve = nil
			}

			switch parts[1] {
			case "SHA-1":
				h = sha1.New()
			case "SHA-224":
				h = sha256.New224()
			case "SHA-256":
				h = sha256.New()
			case "SHA-384":
				h = sha512.New384()
			case "SHA-512":
				h = sha512.New()
			default:
				h = nil
			}

			continue
		}

		if h == nil || pub.Curve == nil {
			continue
		}

		switch {
		case strings.HasPrefix(line, "Msg = "):
			if msg, err = hex.DecodeString(line[6:]); err != nil {
				t.Fatalf("failed to decode message on line %d: %s", lineNo, err)
			}
		case strings.HasPrefix(line, "Qx = "):
			pub.X = fromHex(line[5:])
		case strings.HasPrefix(line, "Qy = "):
			pub.Y = fromHex(line[5:])
		case strings.HasPrefix(line, "R = "):
			r = fromHex(line[4:])
		case strings.HasPrefix(line, "S = "):
			s = fromHex(line[4:])
		case strings.HasPrefix(line, "Result = "):
			expected := line[9] == 'P'
			h.Reset()
			h.Write(msg)
			hashed := h.Sum(hashed[:0])
			if Verify(pub, hashed, r, s) != expected {
				t.Fatalf("incorrect result on line %d", lineNo)
			}
		default:
			t.Fatalf("unknown variable on line %d: %s", lineNo, line)
		}
	}
}

func testNegativeInputs(t *testing.T, curve elliptic.Curve, tag string) {
	key, err := GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Errorf("failed to generate key for %q", tag)
	}

	var hash [32]byte
	r := new(big.Int).SetInt64(1)
	r.Lsh(r, 550 /* larger than any supported curve */)
	r.Neg(r)

	if Verify(&key.PublicKey, hash[:], r, r) {
		t.Errorf("bogus signature accepted for %q", tag)
	}
}

func TestNegativeInputs(t *testing.T) {
	testNegativeInputs(t, elliptic.P224(), "p224")
	testNegativeInputs(t, elliptic.P256(), "p256")
	testNegativeInputs(t, elliptic.P384(), "p384")
	testNegativeInputs(t, elliptic.P521(), "p521")
}

func testCollectiveSignandVerify(t *testing.T, c elliptic.Curve, tag string, timetemp1, timetemp2 *int64) {
	var number int
	number = 32
	var priv []*PrivateKey
	var rcomit1 []*big.Int
	var rcomit2 []*big.Int
	var k []*big.Int
	var response []*big.Int

	priv = make([]*PrivateKey, number)
	// priv = new(*PrivateKey[])
	rcomit1 = make([]*big.Int, number)
	rcomit2 = make([]*big.Int, number)
	// rcomit = new(*big.Int[]) 
	k = make([]*big.Int, number)
	// k = new(*big.Int[])
	response = make([]*big.Int, number)

	time1 := time.Now().UnixNano() 
	// response = new(*big.Int[])
	for i := 0; i < number; i++ {
		priv[i], _ = GenerateKey(c, rand.Reader)
		// fmt.Printf("priv[%d]:", i)
		// fmt.Println(priv[i])
		// privtemp, _ := GenerateKey(c, rand.Reader)
		// priv[i] = privtemp
		rcomit1[i], rcomit2[i], k[i], _ = Commit(rand.Reader, priv[i])
		// rcomitment, random, _ := Commit(rand.Reader, priv[i])
		// rcomit[i] = rcomitment
		// k[i] = random
		
	}
	Aggregate := priv[0].PublicKey
	for i := 1; i < number; i++{
		Aggregate.X, Aggregate.Y = Aggregate.Add(Aggregate.X, Aggregate.Y, priv[i].PublicKey.X, priv[i].PublicKey.Y)
	}
	var getcommit1 []*big.Int
	var getcommit2 []*big.Int
	getcommit1 = make([]*big.Int, number)
	getcommit2 = make([]*big.Int, number)
	for i := 0; i < number; i++{
		getcommit1[i] = rcomit1[i]
		getcommit2[i] = rcomit2[i]
	}
	challenge := Challenge(getcommit1, getcommit2, &Aggregate, priv[0])
	hashed := []byte("testing")
	
	for i := 0; i < number; i++{
		response[i], _ = Response(challenge, priv[i], k[i], hashed)
	}


	// ksum :=k[0]
	// prisum :=priv[0]
	// for i := 1; i < number; i++{
	// 	ksum = ksum.Add(ksum, k[i])
	// 	prisum.D = prisum.D.Add(prisum.D, priv[i].D)

	// }
	// N := c.Params().N
	// ksumcommit, _ := priv[0].Curve.ScalarBaseMult(ksum.Bytes())
	// ksumcommit.Mod(ksumcommit, N)
	// fmt.Println("before hash:",ksumcommit)
	// kk := ksumcommit.Bytes()
	// kkchanll := hashToInt(kk, c) 
	// privsumcommit1, privsumcommit2 := priv[0].Curve.ScalarBaseMult(prisum.D.Bytes())


	// ksumcommit.Mod(ksumcommit,N)
	// fmt.Println("ksumc:",kkchanll)
	// fmt.Println("privsum1:",privsumcommit1,privsumcommit2)
	// fmt.Println("privsum2:",prisum.PublicKey)  priv[0].PublicKey
	
	var tempresponse []*big.Int
	tempresponse = make([]*big.Int, number)
	for i := 0; i < number; i++ {
		tempresponse[i] = response[i]
	}
	R, S := FinalResponse(challenge, response, priv[0])
	// var Aggregate *PublicKey
	// Aggregate = &priv[0].PublicKey
	// fmt.Println(number)

	time2 := time.Now().UnixNano() 
	
	// fmt.Println("aggrega:",Aggregate)
	
	// Aggregate = AggregatePublickey(priv.PublicKey)
	if !Verify(&Aggregate, hashed, R, S) {
		t.Errorf("%s, Verify failed", tag)
	}
	time3 := time.Now().UnixNano() 
	*timetemp1 += time2 - time1
	*timetemp2 += time3 - time2
	//fmt.Println("sign:",time2-time1)
	//fmt.Println("verify:",time3-time2)

	
}

func TestCollectiveSignVerify(t *testing.T) {
	var timetemp1, timetemp2 int64
	for i :=0; i < 100; i ++ {
		testCollectiveSignandVerify(t, elliptic.P256(), "p256", &timetemp1, &timetemp2)
	}
	fmt.Println("sign:",timetemp1)
	fmt.Println("verify:",timetemp2)
}


/* func testCollectiveSignandVerify(t *testing.T, c elliptic.Curve, tag string) {
	var number int
	number = 16384
	var priv []*PrivateKey
	var rcomit1 []*Commitment
	var k []*big.Int
	var response []*big.Int

	priv = make([]*PrivateKey, number)
	// priv = new(*PrivateKey[])
	rcomit1 = make([]*big.Int, number)
	// rcomit = new(*big.Int[]) 
	k = make([]*big.Int, number)
	// k = new(*big.Int[])
	response = make([]*big.Int, number)
	// response = new(*big.Int[])
	for i := 0; i < number; i++ {
		priv[i], _ = GenerateKey(c, rand.Reader)
		// fmt.Printf("priv[%d]:", i)
		// fmt.Println(priv[i])
		// privtemp, _ := GenerateKey(c, rand.Reader)
		// priv[i] = privtemp
		rcomit1[i].X, rcomit2[i].Y, k[i], _ = Commit(rand.Reader, priv[i])
		// rcomitment, random, _ := Commit(rand.Reader, priv[i])
		// rcomit[i] = rcomitment
		// k[i] = random
		
	}
	challenge := Challenge(rcomit1,  priv[0])
	hashed := []byte("testing")
	
	for i := 0; i < number; i++{
		response[i], _ = Response(challenge, priv[i], k[i], hashed)
	}


	// ksum :=k[0]
	// prisum :=priv[0]
	// for i := 1; i < number; i++{
	// 	ksum = ksum.Add(ksum, k[i])
	// 	prisum.D = prisum.D.Add(prisum.D, priv[i].D)

	// }
	// N := c.Params().N
	// ksumcommit, _ := priv[0].Curve.ScalarBaseMult(ksum.Bytes())
	// ksumcommit.Mod(ksumcommit, N)
	// fmt.Println("before hash:",ksumcommit)
	// kk := ksumcommit.Bytes()
	// kkchanll := hashToInt(kk, c) 
	// privsumcommit1, privsumcommit2 := priv[0].Curve.ScalarBaseMult(prisum.D.Bytes())


	// ksumcommit.Mod(ksumcommit,N)
	// fmt.Println("ksumc:",kkchanll)
	// fmt.Println("privsum1:",privsumcommit1,privsumcommit2)
	// fmt.Println("privsum2:",prisum.PublicKey)  priv[0].PublicKey
	
	R, S := FinalResponse(challenge, response, priv[0])
	var Aggregate *PublicKey
	Aggregate = &priv[0].PublicKey
	// fmt.Println(number)


	for i := 1; i < number; i++{
		Aggregate.X, Aggregate.Y = Aggregate.Add(Aggregate.X, Aggregate.Y, priv[i].PublicKey.X, priv[i].PublicKey.Y)
	}
	// fmt.Println("aggrega:",Aggregate)
	if !Verify(Aggregate, hashed, R, S) {
		t.Errorf("%s, Verify failed", tag)
	}
	
}

func TestCollectiveSignVerify(t *testing.T) {
	testCollectiveSignandVerify(t, elliptic.P256(), "p256")
} */