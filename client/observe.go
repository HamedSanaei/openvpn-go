package client

import "time"

// EventKind identifies a bounded lifecycle transition.
type EventKind string

const (
	EventDialing        EventKind = "dialing"
	EventHandshaking    EventKind = "handshaking"
	EventAttemptFailed  EventKind = "attempt_failed"
	EventRetryScheduled EventKind = "retry_scheduled"
	EventConnected      EventKind = "connected"
	EventDisconnected   EventKind = "disconnected"
	EventClosing        EventKind = "closing"
	EventClosed         EventKind = "closed"
)

// Event contains fixed lifecycle fields. EndpointIndex refers to the
// original declared order, and is -1 for client-wide events.
type Event struct {
	Sequence      uint64
	Time          time.Time
	Kind          EventKind
	EndpointIndex int
	Code          ErrorCode
	RetryAfter    time.Duration
}

// Stats reports lifetime counters and the current connection snapshot.
// Traffic counters count successfully forwarded IP packets and bytes.
type Stats struct {
	State               ClientState
	ActiveEndpointIndex int
	ConnectedSince      time.Time
	Attempts            uint64
	AttemptFailures     uint64
	Connections         uint64
	Disconnects         uint64
	Reconnects          uint64
	PacketsSent         uint64
	BytesSent           uint64
	PacketsReceived     uint64
	BytesReceived       uint64
	LastError           ErrorCode
}

// Stats returns an aggregate snapshot. ActiveEndpointIndex is -1 without a
// live session. Packet and byte counters may advance during the snapshot.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	active := c.liveConnection()
	stats := c.stats
	stats.State = c.state
	stats.ActiveEndpointIndex = -1
	if active != nil {
		stats.ActiveEndpointIndex = active.index
	} else {
		stats.ConnectedSince = time.Time{}
		if stats.State == StateConnected {
			stats.State = StateIdle
		}
	}
	stats.PacketsSent, stats.BytesSent = c.sent.Load()
	stats.PacketsReceived, stats.BytesReceived = c.recv.Load()
	return stats
}

// Events returns a copy of up to 64 recent events newer than afterSequence.
// Pass zero to read all retained events. A gap indicates overwritten events.
func (c *Client) Events(afterSequence uint64) []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.liveConnection()
	return c.events.After(afterSequence)
}

// record and the lifecycle helpers below must be called with c.mu held.
func (c *Client) record(kind EventKind, index int, code ErrorCode, delay time.Duration) {
	c.events.Append(Event{
		Sequence: c.events.Sequence() + 1, Time: time.Now(), Kind: kind,
		EndpointIndex: index, Code: code, RetryAfter: delay,
	})
}

func (c *Client) disconnected(active *connection, code ErrorCode) {
	if code != "" {
		c.stats.Disconnects++
		c.stats.LastError = code
	}
	c.record(EventDisconnected, active.index, code, 0)
}

func (c *Client) stateSnapshot() ClientState {
	if c.liveConnection() == nil && c.state == StateConnected {
		return StateIdle
	}
	return c.state
}

type sessionStatus interface {
	Done() <-chan struct{}
	Err() error
}

func (c *Client) liveConnection() *connection {
	active := c.active
	if active == nil {
		return nil
	}
	link, ok := active.link.(sessionStatus)
	if !ok {
		return active
	}
	select {
	case <-link.Done():
		if c.run == nil {
			c.active = nil
			c.state = StateIdle
			c.disconnected(active, packetErrorCode(link.Err(), CodeNetwork))
		}
		return nil
	default:
		return active
	}
}
