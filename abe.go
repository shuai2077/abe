package main

import (
	"crypto/aes"
	cbc "crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"fmt"
	"github.com/fentec-project/bn256"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/gofe/data"
	"github.com/fentec-project/gofe/sample"
	"math/big"
)

type ABEParams struct {
	P *big.Int
}

type ABE struct {
	Params *ABEParams
}

func NewABE(l int) *ABE {
	return &ABE{Params: &ABEParams{
		P: bn256.Order,
	}}
}

type ABESeckey struct {
	PartG2_s *bn256.G2
}

type ABEPubkey struct {
	PartG2_p *bn256.G2
	PartGT   *bn256.GT
	//h map[string]*bn256.G2
}

func (a *ABE) Setup(gamma []string) (*ABEPubkey, *ABESeckey, error) {
	sampler := sample.NewUniform(a.Params.P)
	val, err := data.NewRandomVector(2, sampler)
	if err != nil {
		return nil, nil, err
	}

	//partInt := [2]*big.Int{val[0], val[1]}
	partG2_s := new(bn256.G2).ScalarBaseMult(val[0]) // g^alpha
	partG2_p := new(bn256.G2).ScalarBaseMult(val[1]) // g^a
	partGT := new(bn256.GT).ScalarBaseMult(val[0])

	return &ABEPubkey{PartG2_p: partG2_p, PartGT: partGT}, &ABESeckey{PartG2_s: partG2_s}, nil
}

type ABEAttribKeys struct {
	K         *bn256.G2
	L         *bn256.G1
	Kx        []*bn256.G2
	AttribToI map[string]int
}

func (a *ABE) KeyGen(gamma []string, pk *ABEPubkey, msk *ABESeckey) (*ABEAttribKeys, error) {
	sampler := sample.NewUniform(a.Params.P)
	t, err := sampler.Sample()
	if err != nil {
		return nil, err
	}

	K := new(bn256.G2).Add(msk.PartG2_s, new(bn256.G2).ScalarMult(pk.PartG2_p, t))
	L := new(bn256.G1).ScalarBaseMult(t)

	Kx := make([]*bn256.G2, len(gamma))
	attribToI := make(map[string]int)
	for i, s := range gamma {
		hsi, err := bn256.HashG2(s)
		if err != nil {
			return nil, err
		}
		hsi.ScalarMult(hsi, t)

		Kx[i] = hsi

		attribToI[s] = i
	}

	return &ABEAttribKeys{K: K, L: L, Kx: Kx, AttribToI: attribToI}, nil
}

type ABECipher struct {
	C      *bn256.GT
	CPrime *bn256.G1
	Ci     []*bn256.G2
	Di     []*bn256.G1
	Msp    *abe.MSP
	SymEnc []byte // symmetric encryption of the message
	Iv     []byte // initialization vector for symmetric encryption
}

func (a *ABE) Encrypt(msg string, msp *abe.MSP, pk *ABEPubkey) (*ABECipher, error) {
	if len(msp.Mat) == 0 || len(msp.Mat[0]) == 0 {
		return nil, fmt.Errorf("empty msp matrix")
	}

	attrib := make(map[string]bool)
	for _, i := range msp.RowToAttrib {
		if attrib[i] {
			return nil, fmt.Errorf("some attributes correspond to" +
				"multiple rows of the MSP struct, the scheme is not secure")
		}
		attrib[i] = true
	}

	// msg is encrypted using CBC, with a random key that is encapsulated
	// with ABE
	_, keyGt, err := bn256.RandomGT(rand.Reader)
	if err != nil {
		return nil, err
	}
	keyCBC := sha256.Sum256([]byte(keyGt.String()))

	c, err := aes.NewCipher(keyCBC[:])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, c.BlockSize())
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	encrypterCBC := cbc.NewCBCEncrypter(c, iv)

	msgByte := []byte(msg)

	// message is padded according to pkcs7 standard
	padLen := c.BlockSize() - (len(msgByte) % c.BlockSize())
	msgPad := make([]byte, len(msgByte)+padLen)
	copy(msgPad, msgByte)
	for i := len(msgByte); i < len(msgPad); i++ {
		msgPad[i] = byte(padLen)
	}

	symEnc := make([]byte, len(msgPad))
	encrypterCBC.CryptBlocks(symEnc, msgPad)

	sampler := sample.NewUniform(a.Params.P)
	v, err := data.NewRandomVector(msp.Mat.Cols(), sampler)
	if err != nil {
		return nil, err
	}
	lamma, err := msp.Mat.MulVec(v)
	if err != nil {
		return nil, err
	}

	Ci := make([]*bn256.G2, len(msp.Mat))
	Di := make([]*bn256.G1, len(msp.Mat))
	r, err := data.NewRandomVector(len(msp.Mat), sampler)
	if err != nil {
		return nil, err
	}
	for i := 0; i < msp.Mat.Rows(); i++ {
		hsi, err := bn256.HashG2(msp.RowToAttrib[i])
		if err != nil {
			return nil, err
		}
		hsi = hsi.ScalarMult(hsi, r[i])
		hsi.Neg(hsi)
		//var partCi *bn256.G2
		if lamma[i].Sign() == -1 {
			lamma[i].Neg(lamma[i])
			partCi := new(bn256.G2).ScalarMult(pk.PartG2_p, lamma[i])
			partCi.Neg(partCi)
			partCi.Add(partCi, hsi)
			Ci[i] = partCi
		} else {
			partCi := new(bn256.G2).ScalarMult(pk.PartG2_p, lamma[i])
			partCi.Add(partCi, hsi)
			Ci[i] = partCi
		}

		partDi := new(bn256.G1).ScalarBaseMult(r[i])

		Di[i] = partDi
	}

	C := new(bn256.GT).ScalarMult(pk.PartGT, v[0])
	C.Add(C, keyGt)

	CPrime := new(bn256.G1).ScalarBaseMult(v[0])

	return &ABECipher{C: C, CPrime: CPrime, Ci: Ci, Di: Di, Msp: msp, SymEnc: symEnc, Iv: iv}, nil
}

func (a *ABE) Decrypt(cipher *ABECipher, key *ABEAttribKeys, pk *ABEPubkey) (string, error) {
	// find out which attributes are owned
	attribMap := make(map[string]bool)
	for k := range key.AttribToI {
		attribMap[k] = true
	}

	countAttrib := 0
	for i := 0; i < len(cipher.Msp.Mat); i++ {
		if attribMap[cipher.Msp.RowToAttrib[i]] {
			countAttrib++
		}
	}

	// create a matrix of needed keys
	preMatForKey := make([]data.Vector, countAttrib)
	CiForKey := make([]*bn256.G2, countAttrib)
	DiForKey := make([]*bn256.G1, countAttrib)
	rowToAttrib := make([]string, countAttrib)
	countAttrib = 0
	for i := 0; i < len(cipher.Msp.Mat); i++ {
		if attribMap[cipher.Msp.RowToAttrib[i]] {
			preMatForKey[countAttrib] = cipher.Msp.Mat[i] //the matrix
			CiForKey[countAttrib] = cipher.Ci[i]
			DiForKey[countAttrib] = cipher.Di[i]
			rowToAttrib[countAttrib] = cipher.Msp.RowToAttrib[i] //the attribute name
			countAttrib++
		}
	}

	matForKey, err := data.NewMatrix(preMatForKey)
	if err != nil {
		return "", fmt.Errorf("the provided cipher is faulty")
	}

	// matForKey may have a len of 0 if there is a single condition
	if len(matForKey) == 0 {
		return "", fmt.Errorf("provided key is not sufficient for decryption")
	}
	oneVec := data.NewConstantVector(len(matForKey[0]), big.NewInt(0))
	oneVec[0].SetInt64(1)
	alpha, err := data.GaussianEliminationSolver(matForKey.Transpose(), oneVec, a.Params.P)
	if err != nil {
		return "", fmt.Errorf("provided key is not sufficient for decryption")
	}

	// get a CBC key needed for the decryption of msg
	keyGt := new(bn256.GT).Set(cipher.C)

	for i, e := range rowToAttrib {
		CiPairing := bn256.Pair(key.L, CiForKey[i])
		DiPairing := bn256.Pair(DiForKey[i], key.Kx[key.AttribToI[e]])
		if alpha[i].Sign() == -1 {
			alpha[i].Neg(alpha[i])
			partPairing := new(bn256.GT).ScalarMult(new(bn256.GT).Add(CiPairing, DiPairing), alpha[i])
			partPairing.Neg(partPairing)
			keyGt.Add(keyGt, partPairing)
		} else {
			partPairing := new(bn256.GT).ScalarMult(new(bn256.GT).Add(CiPairing, DiPairing), alpha[i])
			keyGt.Add(keyGt, partPairing)
		}
	}
	keyPairing := bn256.Pair(cipher.CPrime, key.K)
	keyPairing.Neg(keyPairing)
	keyGt.Add(keyGt, keyPairing)

	keyCBC := sha256.Sum256([]byte(keyGt.String()))

	c, err := aes.NewCipher(keyCBC[:])
	if err != nil {
		return "", err
	}

	msgPad := make([]byte, len(cipher.SymEnc))
	decrypter := cbc.NewCBCDecrypter(c, cipher.Iv)
	decrypter.CryptBlocks(msgPad, cipher.SymEnc)

	// unpad the message
	padLen := int(msgPad[len(msgPad)-1])
	if (len(msgPad) - padLen) < 0 {
		return "", fmt.Errorf("failed to decrypt")
	}
	msgByte := msgPad[0:(len(msgPad) - padLen)]

	return string(msgByte), nil
}
