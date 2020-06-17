// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2020 The Blocknet developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"golang.org/x/crypto/ripemd160"
	"io"
	"math/big"
)

// MsgSnodePing defines a service node list message which is used to obtain
// the latest service node list from the network.
type MsgSnodePing struct{
	PingPubkey *btcec.PublicKey
	BlockHeight uint32
	BlockHash [32]byte
	PingTime uint32
	Config string
	*MsgSnodeRegistration
	PingSignature *btcec.Signature // compact
	PingSignatureRaw [65]byte // compact
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgSnodePing) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	var err error

	if msg.PingPubkey, err = readCompressedPubkey(r, pver); err != nil {
		return err
	}
	if err = readElement(r, &msg.BlockHeight); err != nil {
		return err
	}
	if err = readElement(r, &msg.BlockHash); err != nil {
		return err
	}
	if err = readElement(r, &msg.PingTime); err != nil {
		return err
	}
	if msg.Config, err = ReadVarString(r, pver); err != nil {
		return err
	}
	if err = msg.MsgSnodeRegistration.BtcDecode(r, pver, enc); err != nil {
		return err
	}
	if msg.PingSignature, msg.PingSignatureRaw, err = readCompactSignature(r, pver); err != nil {
		return err
	}

	// Verify the ping signature

	// Generate the signature's hash
	var b []byte
	buf := bytes.NewBuffer(b)
	if err = writeElements(buf, uint8(btcec.PubKeyBytesLenCompressed), msg.PingPubkey.SerializeCompressed()); err != nil {
		return err
	}
	if err = writeElements(buf, msg.BlockHeight, msg.BlockHash, msg.PingTime); err != nil {
		return err
	}
	if err = WriteVarString(buf, pver, msg.Config); err != nil {
		return err
	}
	if err = msg.MsgSnodeRegistration.BtcEncode(buf, pver, enc); err != nil {
		return err
	}

	sighash := chainhash.DoubleHashB(buf.Bytes())

	var pk *btcec.PublicKey
	var ok bool
	if pk, ok, err = btcec.RecoverCompact(btcec.S256(), msg.PingSignatureRaw[:], sighash); err != nil || !ok {
		if err != nil {
			return err
		} else if !ok {
			return errors.New("snode signature failed validation")
		}
	}

	if bytes.Compare(hash160(pk.SerializeCompressed()), hash160(msg.PingPubkey.SerializeCompressed())) != 0 {
		return errors.New("snode pubkey doesn't match expected")
	}

	if bytes.Compare(hash160(msg.PingPubkey.SerializeCompressed()), hash160(msg.MsgSnodeRegistration.SnodePubkey.SerializeCompressed())) != 0 {
		return errors.New("ping pubkey doesn't match expected snode pubkey")
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgSnodePing) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	var err error

	if err = writeElements(w, uint8(33), msg.PingPubkey.SerializeCompressed()); err != nil {
		return err
	}
	if err = writeElements(w, msg.BlockHeight, msg.BlockHash, msg.PingTime); err != nil {
		return err
	}
	if err = WriteVarString(w, pver, msg.Config); err != nil {
		return err
	}
	if err = msg.MsgSnodeRegistration.BtcEncode(w, pver, enc); err != nil {
		return err
	}
	if err = writeElements(w, uint8(65), msg.PingSignatureRaw); err != nil {
		return err
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgSnodePing) Command() string {
	return CmdSnodePing
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgSnodePing) MaxPayloadLength(pver uint32) uint32 {
	//  1 - compressed snode pubkey length
	// 33 - compressed snode pubkey
	//  4 - block height
	// 32 - block hash (256 bit)
	//  4 - ping time
	//  n - config len (can be uint8, uint16, uint32, uint64) + config string + null terminated string
	//  n - snode registration bytes (see MsgSnodeRegistration.MaxPayloadLength)
	//  1 - snode ping signature length
	// 65 - snode ping signature

	snodePayloadBytes := msg.MsgSnodeRegistration.MaxPayloadLength(pver)
	const configMaxBytes = 100000 // 100kb
	return 1 + 33 + 4 + 32 + 4 + configMaxBytes + snodePayloadBytes + 1 + 65
}

// NewMsgSnodePing returns a new blocknet snode ping message that conforms to the
// Message interface.
func NewMsgSnodePing() *MsgSnodePing {
	r := &MsgSnodePing{}
	r.MsgSnodeRegistration = NewMsgSnodeRegistration()
	return r
}

// MsgSnodePing defines a service node ping message.
type MsgSnodeListPing struct {
	*MsgSnodePing
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgSnodeListPing) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return msg.MsgSnodePing.BtcDecode(r, pver, enc)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgSnodeListPing) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	return msg.MsgSnodePing.BtcEncode(w, pver, enc)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgSnodeListPing) Command() string {
	return CmdSnodeListPing
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgSnodeListPing) MaxPayloadLength(pver uint32) uint32 {
	return msg.MsgSnodePing.MaxPayloadLength(pver)
}

// NewMsgSnodeListPing returns a new blocknet snode list ping message that conforms to the
// Message interface.
func NewMsgSnodeListPing() *MsgSnodeListPing {
	return &MsgSnodeListPing{NewMsgSnodePing()}
}

// MsgSnodeList defines a service node list message which is used to obtain
// the latest service node list from the network.
//
// This message has no payload.
type MsgSnodeList struct{}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgSnodeList) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgSnodeList) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgSnodeList) Command() string {
	return CmdSnodeList
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgSnodeList) MaxPayloadLength(pver uint32) uint32 {
	return 0
}

// NewMsgSnodeList returns a new blocknet snode list ping message that conforms to the
// Message interface.
func NewMsgSnodeList() *MsgSnodeList {
	return &MsgSnodeList{}
}

// MsgSnodeRegistration defines a service node registration message.
type MsgSnodeRegistration struct{
	SnodePubkey *btcec.PublicKey
	SnodeTier uint8
	SnodePaymentAddress [20]byte
	SnodeCollateral []OutPoint
	SnodeBestBlock uint32
	SnodeBestBlockHash [32]byte
	SnodeSignature *btcec.Signature
	SnodeSignatureRaw [65]byte
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgSnodeRegistration) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	var err error

	if msg.SnodePubkey, err = readCompressedPubkey(r, pver); err != nil {
		return err
	}
	if err = readElement(r, &msg.SnodeTier); err != nil {
		return err
	}
	if err = readElement(r, &msg.SnodePaymentAddress); err != nil {
		return err
	}
	if msg.SnodeCollateral, err = readCollateralOutpoints(r, pver); err != nil {
		return err
	}
	if err = readElement(r, &msg.SnodeBestBlock); err != nil {
		return err
	}
	if err = readElement(r, &msg.SnodeBestBlockHash); err != nil {
		return err
	}
	if msg.SnodeSignature, msg.SnodeSignatureRaw, err = readCompactSignature(r, pver); err != nil {
		return err
	}

	return nil

	// TODO Blocknet Service node sig verification requires access to collateral pubkey

	/*
	// Generate the signature's hash
	var b []byte
	buf := bytes.NewBuffer(b)
	if err = writeElements(buf, uint8(btcec.PubKeyBytesLenCompressed), msg.SnodePubkey.SerializeCompressed()); err != nil {
		return err
	}
	if err = writeElements(buf, msg.SnodeTier, msg.SnodePaymentAddress); err != nil {
		return err
	}
	if err = WriteVarInt(w, pver, uint64(len(msg.SnodeCollateral))); err != nil {
		return err
	}
	for _, v := range msg.SnodeCollateral {
		if err = writeElements(buf, v.Hash, v.Index); err != nil {
			return err
		}
	}
	if err = writeElement(buf, msg.SnodeBestBlock); err != nil {
		return err
	}
	if err = writeElement(buf, msg.SnodeBestBlockHash); err != nil {
		return err
	}

	sighash := chainhash.DoubleHashB(buf.Bytes())

	var pk *btcec.PublicKey
	var ok bool
	if pk, ok, err = btcec.RecoverCompact(btcec.S256(), SnodeSignatureRaw, sighash); err != nil || !ok {
		if err != nil {
			return err
		} else if !ok {
			return errors.New("snode signature failed validation")
		}
	}

	collateralKeyID := msg.SnodeCollateral[0].RipeMD
	if bytes.Compare(hash160(pk.SerializeCompressed()), collateralKeyID) != 0 {
		return errors.New("snode pubkey doesn't match expected")
	}

	return nil
	*/
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgSnodeRegistration) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	var err error

	if err = writeElements(w, uint8(btcec.PubKeyBytesLenCompressed), msg.SnodePubkey.SerializeCompressed()); err != nil {
		return err
	}
	if err = writeElements(w, msg.SnodeTier, msg.SnodePaymentAddress); err != nil {
		return err
	}
	if err = WriteVarInt(w, pver, uint64(len(msg.SnodeCollateral))); err != nil {
		return err
	}
	for _, v := range msg.SnodeCollateral {
		if err = writeElements(w, v.Hash, v.Index); err != nil {
			return err
		}
	}
	if err = writeElement(w, msg.SnodeBestBlock); err != nil {
		return err
	}
	if err = writeElement(w, msg.SnodeBestBlockHash); err != nil {
		return err
	}
	if err = writeElements(w, uint8(65), msg.SnodeSignatureRaw); err != nil { // compact sig length
		return err
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgSnodeRegistration) Command() string {
	return CmdSnodeReg
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgSnodeRegistration) MaxPayloadLength(pver uint32) uint32 {
	//  1 - compressed snode pubkey length
	// 33 - compressed snode pubkey
	//  1 - tier
	// 20 - payment address
	//  1 - outpoints len
	//  n - list of utxo collateral outpoints (max 10)
	//    32 - hash of utxo
	//     4 - vout of utxo
	//     ...
	//  4 - best block
	// 32 - best block hash
	//  1 - snode signature length
	// 65 - snode signature
	return 1 + 33 + 1 + 20 + 1 + (32+4)*10 + 4 + 32 + 1 + 65
}

// MsgSnodeRegistration returns a new blocknet snode list ping message that conforms to the
// Message interface.
func NewMsgSnodeRegistration() *MsgSnodeRegistration {
	return &MsgSnodeRegistration{}
}

// readCompactSignature reads a compact signature from the reader.
func readCompactSignature(r io.Reader, pver uint32) (*btcec.Signature, [65]byte, error) {
	var empty [65]byte
	// Read the signature length
	sigLen, err := ReadVarInt(r, pver)
	if err != nil {
		return nil, empty, err
	}
	if sigLen != 65 {
		return nil, empty, errors.New("bad snode signature length")
	}
	var sig [65]byte
	if err = readElement(r, &sig); err != nil {
		return nil, empty, err
	}
	// format is <header byte><bitlen R><bitlen S>
	bitlen := (btcec.S256().BitSize + 7) / 8
	rsig := &btcec.Signature{
		R: new(big.Int).SetBytes(sig[1 : bitlen+1]),
		S: new(big.Int).SetBytes(sig[bitlen+1:]),
	}
	return rsig, sig, nil
}

// readCompressedPubkey reads a compact pubkey from the reader.
func readCompressedPubkey(r io.Reader, pver uint32) (*btcec.PublicKey, error) {
	// Read the pubkey length
	keyLen, err := ReadVarInt(r, pver)
	if err != nil {
		return nil, err
	}
	if keyLen > btcec.PubKeyBytesLenCompressed {
		return nil, errors.New("only compressed pubkeys allowed in snode ping")
	}
	var pubkey [btcec.PubKeyBytesLenCompressed]byte
	if err = readElement(r, &pubkey); err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(pubkey[:], btcec.S256())
}

// readCollateralOutpoints reads snode collateral outpoints from the reader.
func readCollateralOutpoints(r io.Reader, pver uint32) ([]OutPoint, error) {
	// Read the number of collateral outpoints
	outpointsLen, err := ReadVarInt(r, pver)
	if err != nil {
		return nil, err
	}
	if outpointsLen == 0 {
		return nil, errors.New("bad snode collateral")
	}
	outpoints := make([]OutPoint, int(outpointsLen))
	for i := 0; i < int(outpointsLen); i++ {
		var outpoint OutPoint
		err := readOutPoint(r, pver, 0, &outpoint)
		if err != nil {
			return nil, err
		}
		outpoints[i] = outpoint
	}
	return outpoints, nil
}

// hash160 returns the RIPEMD160 hash of the SHA-256 HASH of the given data.
func hash160(data []byte) []byte {
	h := sha256.Sum256(data)
	return ripemd160h(h[:])
}

// ripemd160h returns the RIPEMD160 hash of the given data.
func ripemd160h(data []byte) []byte {
	h := ripemd160.New()
	h.Write(data)
	return h.Sum(nil)
}