package discordgo

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/jamesprial/dave-go-bindings/dave"
)

// daveState holds all DAVE E2EE state for a voice connection.
// The session field is protected by mu. The encryptor and decryptor are
// owned exclusively by opusSender and opusReceiver goroutines respectively.
type daveState struct {
	mu sync.Mutex

	session *dave.Session

	// Owned exclusively by opusSender goroutine -- no mutex needed
	encryptor  *dave.Encryptor
	senderKR   *dave.KeyRatchet
	senderKRCh chan *dave.KeyRatchet

	// Owned exclusively by opusReceiver goroutine -- no mutex needed
	decryptor    *dave.Decryptor
	receiverKR   *dave.KeyRatchet
	receiverKRCh chan *dave.KeyRatchet

	protocolVersion     uint16
	pendingTransitionID uint16
	pendingVersion      uint16
	active              bool

	ssrc    uint32
	userID  string
	guildID uint64

	// closed when DAVE handshake completes (first activation)
	readyCh     chan struct{}
	readyOnce   sync.Once
	closedOnce  sync.Once
}

func newDaveState(userID string, guildID uint64, ssrc uint32) (*daveState, error) {
	session, err := dave.NewSession("", func(source, reason string) {
		// MLS failure callback -- logged at the session level
	})
	if err != nil {
		return nil, fmt.Errorf("creating DAVE session: %w", err)
	}

	enc := dave.NewEncryptor()
	enc.SetPassthroughMode(true)
	enc.AssignSsrcToCodec(ssrc, dave.CodecOpus)

	dec := dave.NewDecryptor()
	dec.TransitionToPassthroughMode(true)

	return &daveState{
		session:      session,
		encryptor:    enc,
		decryptor:    dec,
		senderKRCh:   make(chan *dave.KeyRatchet, 1),
		receiverKRCh: make(chan *dave.KeyRatchet, 1),
		ssrc:         ssrc,
		userID:       userID,
		guildID:      guildID,
		readyCh:      make(chan struct{}),
	}, nil
}

func (ds *daveState) init(version uint16) ([]byte, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	ds.protocolVersion = version
	ds.session.Init(version, ds.guildID, ds.userID)

	kp := ds.session.GetMarshalledKeyPackage()
	if kp == nil {
		return nil, fmt.Errorf("DAVE key package generation returned nil")
	}
	return kp, nil
}

func (ds *daveState) handleExternalSender(data []byte) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.session.SetExternalSender(data)
}

func (ds *daveState) handleWelcome(data []byte) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	result := ds.session.ProcessWelcome(data, nil)
	if result == nil {
		return fmt.Errorf("DAVE ProcessWelcome returned nil")
	}
	defer result.Close()

	// Get our own key ratchet for sending
	kr := ds.session.GetKeyRatchet(ds.userID)
	if kr != nil {
		// Non-blocking send; drop old if channel full
		select {
		case ds.senderKRCh <- kr:
		default:
			// drain and resend
			select {
			case old := <-ds.senderKRCh:
				old.Close()
			default:
			}
			ds.senderKRCh <- kr
		}
	}

	return nil
}

func (ds *daveState) handlePrepareTransition(transitionID uint16, version uint16) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.pendingTransitionID = transitionID
	ds.pendingVersion = version
}

func (ds *daveState) handleExecuteTransition(transitionID uint16) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	if transitionID == ds.pendingTransitionID && ds.pendingVersion > 0 {
		ds.active = true
		ds.readyOnce.Do(func() {
			close(ds.readyCh)
		})
	}

	return nil
}

func (ds *daveState) handlePrepareEpoch(epoch uint64, version uint16) ([]byte, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	ds.active = false
	ds.session.Reset()
	ds.protocolVersion = version
	ds.session.Init(version, ds.guildID, ds.userID)

	kp := ds.session.GetMarshalledKeyPackage()
	if kp == nil {
		return nil, fmt.Errorf("DAVE key package generation returned nil after epoch reset")
	}
	return kp, nil
}

func (ds *daveState) resetForReWelcome() ([]byte, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	ds.session.Reset()
	ds.session.Init(ds.protocolVersion, ds.guildID, ds.userID)

	kp := ds.session.GetMarshalledKeyPackage()
	if kp == nil {
		return nil, fmt.Errorf("DAVE key package generation returned nil after re-welcome reset")
	}
	return kp, nil
}

// encrypt encrypts an opus frame with DAVE E2EE. Called ONLY from opusSender goroutine.
func (ds *daveState) encrypt(frame []byte) ([]byte, error) {
	// Check for new key ratchet (non-blocking)
	select {
	case kr := <-ds.senderKRCh:
		if ds.senderKR != nil {
			ds.senderKR.Close()
		}
		ds.senderKR = kr
		ds.encryptor.SetKeyRatchet(kr)
		ds.encryptor.SetPassthroughMode(false)
	default:
	}

	if !ds.encryptor.HasKeyRatchet() {
		// Still in passthrough mode, return frame as-is
		return frame, nil
	}

	outSize := ds.encryptor.GetMaxCiphertextByteSize(dave.MediaTypeAudio, len(frame))
	outBuf := make([]byte, outSize)
	n, err := ds.encryptor.Encrypt(dave.MediaTypeAudio, ds.ssrc, frame, outBuf)
	if err != nil {
		return nil, err
	}
	return outBuf[:n], nil
}

// decrypt decrypts a DAVE E2EE encrypted opus frame. Called ONLY from opusReceiver goroutine.
func (ds *daveState) decrypt(encrypted []byte) ([]byte, error) {
	// Check for new key ratchet (non-blocking)
	select {
	case kr := <-ds.receiverKRCh:
		if ds.receiverKR != nil {
			ds.receiverKR.Close()
		}
		ds.receiverKR = kr
		ds.decryptor.TransitionToKeyRatchet(kr)
		ds.decryptor.TransitionToPassthroughMode(false)
	default:
	}

	outSize := ds.decryptor.GetMaxPlaintextByteSize(dave.MediaTypeAudio, len(encrypted))
	if outSize <= 0 {
		return encrypted, nil
	}
	outBuf := make([]byte, outSize)
	n, err := ds.decryptor.Decrypt(dave.MediaTypeAudio, encrypted, outBuf)
	if err != nil {
		return nil, err
	}
	return outBuf[:n], nil
}

func (ds *daveState) isActive() bool {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return ds.active
}

func (ds *daveState) reset() {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.session.Reset()
	ds.active = false
}

func (ds *daveState) close() {
	ds.closedOnce.Do(func() {
		if ds.senderKR != nil {
			ds.senderKR.Close()
		}
		if ds.receiverKR != nil {
			ds.receiverKR.Close()
		}
		// Drain channels
		select {
		case kr := <-ds.senderKRCh:
			kr.Close()
		default:
		}
		select {
		case kr := <-ds.receiverKRCh:
			kr.Close()
		default:
		}
		ds.encryptor.Close()
		ds.decryptor.Close()
		ds.session.Close()
	})
}

// parseGuildID converts a guild ID string to uint64.
func parseGuildID(guildID string) uint64 {
	id, _ := strconv.ParseUint(guildID, 10, 64)
	return id
}
