package noise

import "github.com/flynn/noise"

func (nc *NoiseConn) HandshakeStateRead() (err error) {
	nc.readMsgBuf, err = nc.ReadMsg(nc.readMsgBuf[:0])
	if err != nil {
		return err
	}
	var cs1, cs2 *noise.CipherState
	nc.readBuf, cs1, cs2, err = nc.HandshakeState.ReadMessage(nc.readBuf, nc.readMsgBuf)
	if err != nil {
		return err
	}
	nc.SetCipherStates(cs1, cs2)
	nc.HandshakeStateResponsibility = true
	//if nc.rfmValidate != nil {
		//err = nc.rfmValidate(nc.Conn.RemoteAddr(), nc.readMsgBuf)
		//nc.rfmValidate = nil
		//return err
	//}
	return nil
}

func (nc *NoiseConn) HandshakeStateCreate(out, payload []byte) (by []byte, err error) {
	var cs1, cs2 *noise.CipherState
	outlen := len(out)
	out, cs1, cs2, err = nc.HandshakeState.WriteMessage(append(out, make([]byte, 4)...), payload)
	if err != nil {
		return nil, err
	}
	//if nc.rfmValidate != nil {
		// only applies to responders, not initiators.
		//nc.rfmValidate = nil
	//}
	nc.SetCipherStates(cs1, cs2)
	nc.HandshakeStateResponsibility = false
	//nc.readBarrier.Release()
	return out, nc.Frame(out[outlen:], out[outlen+4:])
}

func (nc *NoiseConn) Frame(header, body []byte) (err error) {
	return
}

func (nc *NoiseConn) ReadMsg(b []byte) (by []byte, err error) {
	return
}

func (nc *NoiseConn) SetCipherStates(cs1, cs2 *noise.CipherState) {
	if nc.Initiator {
		nc.send, nc.recv = cs1, cs2
	} else {
		nc.send, nc.recv = cs2, cs1
	}
	if nc.send != nil {
		//nc.readBarrier.Release()
		nc.handshakeHash = nc.HandshakeState.ChannelBinding()
		nc.HandshakeState = nil
	}
}
