// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as
// defined in FIPS 186-3.
//
// This implementation  derives the nonce from an AES-CTR CSPRNG keyed by
// ChopMD(256, SHA2-512(priv.D || entropy || hash)). The CSPRNG key is IRO by
// a result of Coron; the AES-CTR stream is IRO under standard assumptions.
package ecdsa

// References:
//   [NSA]: Suite B implementer's guide to FIPS 186-3,
//     http://www.nsa.gov/ia/_files/ecdsa.pdf
//   [SECG]: SECG, SEC1
//     http://www.secg.org/sec1-v2.pdf

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"fmt"

	"crypto/internal/randutil"
)

// A invertible implements fast inverse mod Curve.Params().N
type invertible interface {
	// Inverse returns the inverse of k in GF(P)
	Inverse(k *big.Int) *big.Int
}

// combinedMult implements fast multiplication S1*g + S2*p (g - generator, p - arbitrary point)
type combinedMult interface {
	CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int)
}

const (
	aesIV = "IV for ECDSA CTR"
)

// PublicKey represents an ECDSA public key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// PrivateKey represents a ECDSA private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

type ecdsaSignature struct {
	R, S *big.Int
}

type ecdsaCommitment struct {
	R, T *big.Int
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

// Sign signs msg with priv, reading randomness from rand. This method is
// intended to support keys where the private part is kept in, for example, a
// hardware module. Common uses should use the Sign function in this package
// directly.
func (priv *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := Sign(rand, priv, msg)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(ecdsaSignature{r, s})
}

var one = new(big.Int).SetInt64(1)

// func (priv *PrivateKey) Commit(rand io.Reader, opts crypto.SignerOpts) ([]byte, error) {
// 	r, t, k, err := Commit(rand, priv)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return asn1.Marshal(ecdsaCommitment{r, t})
// }


func (priv *PrivateKey) Commit(rand io.Reader, opts crypto.SignerOpts) (*big.Int, *big.Int, *big.Int, error) {
	r, t, k, err := Commit(rand, priv)
	if err != nil {
		return nil, nil, nil, err
	}

	return r, t, k, nil
}

func (priv *PrivateKey) Challenge(rand io.Reader, Commit []*big.Int, Commit2 []*big.Int, pub *PublicKey, opts crypto.SignerOpts) (*big.Int, error) {
	challenge := Challenge(Commit, Commit2, pub, priv)
	
	return challenge, nil
}
	



// randFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// GenerateKey generates a public and private key pair.
func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
	k, err := randFieldElement(c, rand)
	if err != nil {
		return nil, err
	}

	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method.
// This has better constant-time properties than Euclid's method (implemented
// in math/big.Int.ModInverse) although math/big itself isn't strictly
// constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

var errZeroParam = errors.New("zero parameter")

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length.  It
// returns the signature as a pair of integers. The security of the private key
// depends on the entropy of rand.
func Sign(rand io.Reader, priv *PrivateKey, hash []byte) (chall, s *big.Int, err error) {
	randutil.MaybeReadByte(rand)
	// Get min(log2(q) / 2, 256) bits of entropy from rand.
	entropylen := (priv.Curve.Params().BitSize + 7) / 16
	if entropylen > 32 {
		entropylen = 32
	}
	entropy := make([]byte, entropylen)
	_, err = io.ReadFull(rand, entropy)
	if err != nil {
		return
	}

	// Initialize an SHA-512 hash context; digest ...
	md := sha512.New()
	md.Write(priv.D.Bytes()) // the private key,
	md.Write(entropy)        // the entropy,
	md.Write(hash)           // and the input hash;
	key := md.Sum(nil)[:32]  // and compute ChopMD-256(SHA-512),
	// which is an indifferentiable MAC.

	
	Aggx := priv.PublicKey.X.Bytes()
	Aggy := priv.PublicKey.Y.Bytes()
	md1 := sha512.New()
	
	md1.Write(Aggx)
	md1.Write(Aggy)
	
	

	// Create an AES-CTR instance to use as a CSPRNG.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// Create a CSPRNG that xors a stream of zeros with
	// the output of the AES-CTR instance.
	csprng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	// See [NSA] 3.4.1
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	//var k, kInv *big.Int
	var k,r,dr *big.Int
	var challenge []byte	
	for {
		for {
			k, err = randFieldElement(c, csprng)
			if err != nil {
				r = nil
				return
			}

			/* if in, ok := priv.Curve.(invertible); ok {
				kInv = in.Inverse(k)
			} else {
				kInv = fermatInverse(k, N) // N != 0
			} */

			r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
			//r.Mul(r,k)
			r.Mod(r, N)
			if r.Sign() != 0 {
				break
			}
		}
		//chall:=r		
		e := hashToInt(hash, c)	
		challenge = r.Bytes()
		md1.Write(challenge)
		mdbyte := md1.Sum(nil)
		chall = hashToInt(mdbyte, c)
		// chall = hashToInt(challenge, c)

		// chall:=sha512.New()
		// chall.Write(challenge)
		// chall.Sum(nil)
		//chall.Mod(chall, N)
		s = new(big.Int).Mul(priv.D, e)
		dr = new(big.Int).Mul(k, chall)
		s.Sub(dr, s)
		//s.Mul(s, kInv)
		s.Mod(s, N) // N != 0
		if s.Sign() != 0 {
			break
		}
	}

	return
}
func Commit(rand io.Reader, priv *PrivateKey) (r,t,k *big.Int, err error) {
	entropylen := (priv.Curve.Params().BitSize + 7) / 16
	if entropylen > 32 {
		entropylen = 32
	}
	entropy := make([]byte, entropylen)
	_, err = io.ReadFull(rand, entropy)
	if err != nil {
		return nil, nil, nil, err
	}

	md := sha512.New()
	// md.Write(priv.D.Bytes()) // the private key,
	md.Write(entropy)     
	key := md.Sum(nil)[:32]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	
	csprng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, nil, errZeroParam
	}
	//var k *big.Int

	for {
		k, err =randFieldElement(c, csprng)
		if err != nil {
			r = nil
			t = nil
			k = nil
			return
		}

		r, t = priv.Curve.ScalarBaseMult(k.Bytes())
		//r, t = c.ScalarBaseMult(k.Bytes())
		// r.Mod(r,N)
		// t.Mod(r,N)
		 if r.Sign() != 0 && t.Sign() != 0 {
			 break
		}
	}
	return 
}

func Challenge(Commit []*big.Int, Commit2 []*big.Int, aggregate *PublicKey, priv *PrivateKey) (chall *big.Int) {
	var tempChallenge,tempChallenge2 *big.Int
	tempChallenge = Commit[0]
	tempChallenge2 = Commit2[0]
	c := priv.PublicKey.Curve
	// N := c.Params().N
	count := len(Commit)
	// fmt.Println(count)
	// for _, commit := range Commit {
	// 	tempChallenge = tempChallenge.Add(commit, tempChallenge)
	// }
	for i := 1; i < count; i++ {
		 tempChallenge, tempChallenge2 =c.Add(tempChallenge, tempChallenge2, Commit[i], Commit2[i])
	}
	// tempChallenge.Mod(tempChallenge, N)
	// fmt.Println("before hash chall:", tempChallenge,tempChallenge2)
	if tempChallenge.Sign() == 0{
		fmt.Println("error to challenge")
	}
	Challenge := tempChallenge.Bytes()
	Aggx := aggregate.X.Bytes()
	Aggy := aggregate.Y.Bytes()
	md := sha512.New()
	md.Write(Aggx)
	md.Write(Aggy)
	md.Write(Challenge)
	mdbyte := md.Sum(nil)
	// md.Write(aggregate)
	chall = hashToInt(mdbyte, c) 
	// fmt.Println("chall:",chall)
	return
}

/* func Commit(rand io.Reader, priv *PrivateKey) (commitment *Commitment, k *big.Int, err error) {
	entropylen := (priv.Curve.Params().BitSize + 7) / 16
	if entropylen > 32 {
		entropylen = 32
	}
	entropy := make([]byte, entropylen)
	_, err = io.ReadFull(rand, entropy)
	if err != nil {
		return nil, nil, err
	}

	md := sha512.New()
	// md.Write(priv.D.Bytes()) // the private key,
	md.Write(entropy)     
	key := md.Sum(nil)[:32]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	
	csprng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, nil, errZeroParam
	}
	//var k *big.Int

	for {
		k, err =randFieldElement(c, csprng)
		if err != nil {
			r = nil
			t = nil
			k = nil
			return
		}

		commitment.X, commitment.Y = priv.Curve.ScalarBaseMult(k.Bytes())
		//r, t = c.ScalarBaseMult(k.Bytes())
		// r.Mod(r,N)
		// t.Mod(r,N)
		 if commitment.X.Sign() != 0 && commitement.Y.Sign() != 0 {
			 break
		}
	}
	return 
}

func Challenge(Commit []*Commitment, priv *PrivateKey) (chall *big.Int) {
	var tempChallenge,tempChallenge2 *big.Int
	tempChallenge = Commit[0]
	tempChallenge2 = Commit2[0]
	c := priv.PublicKey.Curve
	// N := c.Params().N
	count := len(Commit)
	// fmt.Println(count)
	// for _, commit := range Commit {
	// 	tempChallenge = tempChallenge.Add(commit, tempChallenge)
	// }
	for i := 1; i < count; i++ {
		 tempChallenge, tempChallenge2 =c.Add(tempChallenge, tempChallenge2, Commit.X, Commit.Y)
	}
	// tempChallenge.Mod(tempChallenge, N)
	// fmt.Println("before hash chall:", tempChallenge,tempChallenge2)
	if tempChallenge.Sign() == 0{
		fmt.Println("error to challenge")
	}
	Challenge := tempChallenge.Bytes()
	chall = hashToInt(Challenge, c) 
	// fmt.Println("chall:",chall)
	return
}
 */
func AggregatePublickey(pub []*PrivateKey) *PublicKey {
	var Aggregate *PublicKey
	Aggregate = &pub[0].PublicKey
	for i := 1; i < len(pub); i++ {
		Aggregate.X, Aggregate.Y = Aggregate.Add(Aggregate.X, Aggregate.Y, pub[i].X, pub[i].Y)
	}
	return Aggregate
}

func Response(chall *big.Int, priv *PrivateKey, k *big.Int, hash []byte)(s *big.Int, err error) {
	for{
		c := priv.PublicKey.Curve
		e := hashToInt(hash, c)
		s = new(big.Int).Mul(priv.D, e)
		dr := new(big.Int).Mul(k, chall)
		N := c.Params().N
		s.Sub(dr, s)
		s.Mod(s, N)
		if s.Sign() != 0 {
			break
		}	
	}
	return
} 

func FinalResponse(r *big.Int, s []*big.Int, priv *PrivateKey)(R, S *big.Int){
	R=r
	var temps *big.Int
	temps = s[0]
	c := priv.PublicKey.Curve
	N := c.Params().N
	// for _, Response := range s {
	// 	temps = temps.Add(Response, temps)
	// }
	// fmt.Println(len(s))
	for i := 1; i < len(s); i++ {
		temps.Add(temps, s[i])
	}
	temps.Mod(temps,N)
	if temps.Sign() == 0 {
		fmt.Println("error to FinalResponse")
	}
	S = temps
	// fmt.Println("S:",S)
	return
	
}
// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
	// See [NSA] 3.4.2
	c := pub.Curve
	N := c.Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 {
		// fmt.Println("none range")
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		// fmt.Println("out of range")
		return false
	}
	////chall:=r
	// challenge := r.Bytes()  origin
	// r.Mod(r, N)     origin
	e := hashToInt(hash, c)
	// chall := hashToInt(challenge,c)
	///chall.Mod(chall, N)
	//
	var w *big.Int
	if in, ok := c.(invertible); ok {
		// w = in.Inverse(chall)  origin
		w = in.Inverse(r)
	} else {
		// w = new(big.Int).ModInverse(chall, N)  origin
		w = new(big.Int).ModInverse(r, N)
	} 

	u2:=e.Mul(e, w)
	//u2:=r.Mul(e, w)
	u2.Mod(u2, N)
	//u1 := s.Mul(s, w)
	u1:=s.Mul(s, w)
	u1.Mod(u1, N)
	//u2 := e.Mul(e, w)
	
	

	// Check if implements S1*p + S2*g
	var x, y *big.Int
	if opt, ok := c.(combinedMult); ok {
		//S1*g + S2*p (g - generator, p - arbitrary point)
		x, y = opt.CombinedMult(pub.X, pub.Y, u1.Bytes(), u2.Bytes())
	} else {
		//ScalarBaseMult returns k*G, where G is the base point of the group
		x1, y1 := c.ScalarBaseMult(u1.Bytes())
		// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
		x2, y2 := c.ScalarMult(pub.X, pub.Y, u2.Bytes())
		x, y = c.Add(x1, y1, x2, y2)
	}

	x.Mod(x, N)
	if x.Sign() == 0 && y.Sign() == 0 {
		// fmt.Println("x is not right")
		return false
	}


	challenge := x.Bytes()

	Aggx := pub.X.Bytes()
	Aggy := pub.Y.Bytes()
	md := sha512.New()
	md.Write(Aggx)
	md.Write(Aggy)
	md.Write(challenge)
	mdbyte := md.Sum(nil)
	x= hashToInt(mdbyte, c)
	// x= hashToInt(challenge, c)
	if x.Cmp(r) != 0 {
		// fmt.Println("not equal")
	}
	return x.Cmp(r) == 0 
	//  return x.Cmp(chall) == 0  origin
}

type zr struct {
	io.Reader
}

// Read replaces the contents of dst with zeros.
func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}


