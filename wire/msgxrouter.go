// Copyright (c) 2020 The Blocknet developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"io"
)

// NewMsgXRouter returns a new blocknet xrouter message that conforms to the
// Message interface.
func NewMsgXRouter() *MsgXRouter {
	return &MsgXRouter{}
}

// MsgXRouter defines an xrouter message.
type MsgXRouter struct{}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgXRouter) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgXRouter) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	return nil
}

// Command returns the protocol command string for the message. This is part
// of the Message interface implementation.
func (msg *MsgXRouter) Command() string {
	return CmdXRouter
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver. This is part of the Message interface implementation.
func (msg *MsgXRouter) MaxPayloadLength(pver uint32) uint32 {
	return 0
}