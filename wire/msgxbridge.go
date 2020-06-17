// Copyright (c) 2020 The Blocknet developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"io"
)

// NewMsgXBridge returns a new blocknet xbridge message that conforms to the
// Message interface.
func NewMsgXBridge() *MsgXBridge {
	return &MsgXBridge{}
}

// MsgXBridge defines an xbridge message.
type MsgXBridge struct{}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgXBridge) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgXBridge) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	return nil
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (msg *MsgXBridge) Command() string {
	return CmdXBridge
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgXBridge) MaxPayloadLength(pver uint32) uint32 {
	return 10000 // 10kb
}