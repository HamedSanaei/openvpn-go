package client

import (
	"time"

	"github.com/hamedsanaei/openvpn-go/internal/observability"
	"github.com/hamedsanaei/openvpn-go/internal/session"
)

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

// QueueStats contains drops and the observed maximum occupancy in packets
// for one class of bounded queue.
type QueueStats struct {
	Dropped   uint64
	HighWater uint64
}

// Stats reports lifetime counters and the current connection snapshot.
// Traffic counters count successfully forwarded IP packets and bytes.
// Queue drop totals and high-water marks include a generation through teardown.
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
	PacketDrops         uint64     // packet-local MTU or invalid local input drops
	CiphertextQueue     QueueStats // received DATA_V2 frames before authentication
	InboundQueue        QueueStats // complete authenticated IP packets
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
	if tracked := c.observedConnection(); tracked != nil {
		raw, inbound := connectionQueues(tracked)
		mergeQueue(&stats.CiphertextQueue, raw)
		mergeQueue(&stats.InboundQueue, inbound)
	}
	stats.PacketsSent, stats.BytesSent = c.sent.Load()
	stats.PacketsReceived, stats.BytesReceived = c.recv.Load()
	stats.PacketDrops = c.packetDrops.Load()
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
	c.finishGeneration(active, code)
}

// AttemptStage identifies the final stage reached by a connection attempt.
type AttemptStage string

const (
	StageResolve        AttemptStage = "resolve"
	StageDial           AttemptStage = "dial"
	StageControl        AttemptStage = "control"
	StageCertificate    AttemptStage = "certificate"
	StageAuthentication AttemptStage = "authentication"
	StageConnected      AttemptStage = "connected"
)

// AttemptPhase identifies the last protocol milestone reached by an attempt.
type AttemptPhase = observability.Phase

const (
	PhaseAdmission       = observability.PhaseAdmission
	PhaseTransport       = observability.PhaseTransport
	PhaseResetACK        = observability.PhaseResetACK
	PhaseTLS             = observability.PhaseTLS
	PhaseCredentials     = observability.PhaseCredentials
	PhaseKeyMethodWrite  = observability.PhaseKeyMethodWrite
	PhaseKeyMethodRead   = observability.PhaseKeyMethodRead
	PhaseKeyMethodFields = observability.PhaseKeyMethodFields
	PhasePush            = observability.PhasePush
	PhaseKeyDerivation   = observability.PhaseKeyDerivation
	PhaseDataSetup       = observability.PhaseDataSetup
	PhaseRekeyDrain      = observability.PhaseRekeyDrain
	PhaseRekeyInstall    = observability.PhaseRekeyInstall
)

// AttemptReport uses ordinal endpoints, durations and stable codes. It is
// safe to serialize without exposing endpoint or credential configuration.
type AttemptReport struct {
	Sequence      uint64        `json:"sequence"`
	EndpointIndex int           `json:"endpoint_index"`
	Stage         AttemptStage  `json:"stage"`
	Phase         AttemptPhase  `json:"phase,omitempty"`
	PhaseDuration time.Duration `json:"phase_duration_ns,omitempty"`
	PhaseSteps    uint8         `json:"phase_steps,omitempty"`
	Code          ErrorCode     `json:"code,omitempty"`
	Started       time.Time     `json:"started"`
	Duration      time.Duration `json:"duration_ns"`
	RetryReason   ErrorCode     `json:"retry_reason,omitempty"`
	RetryAfter    time.Duration `json:"retry_after_ns,omitempty"`
	Generation    uint64        `json:"generation,omitempty"`
	CleanupFailed bool          `json:"cleanup_failed,omitempty"`
}

// AttemptReports returns completed attempts newer than afterSequence.
// At most 64 reports are retained. An interrupted attempt is reported even
// when it does not increment the attempt failure counter.
func (c *Client) AttemptReports(afterSequence uint64) []AttemptReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.attempts == nil {
		return nil
	}
	return c.attempts.After(afterSequence)
}

func (c *Client) recordAttempt(report AttemptReport) {
	if c.attempts == nil {
		c.attempts = new(observability.History[AttemptReport])
	}
	c.attempts.Append(report)
}

// RekeyReport identifies a completed soft-reset attempt without peer data.
// A nonzero Code indicates that the attempt did not install data keys.
type RekeyReport struct {
	Generation    uint64        `json:"generation"`
	KeyID         uint8         `json:"key_id"`
	PeerInitiated bool          `json:"peer_initiated"`
	Started       time.Time     `json:"started"`
	Duration      time.Duration `json:"duration_ns"`
	Phase         AttemptPhase  `json:"phase"`
	Code          ErrorCode     `json:"code,omitempty"`
}

// GenerationReport uses connection-local packet and plaintext byte counters.
type GenerationReport struct {
	Generation      uint64    `json:"generation"`
	EndpointIndex   int       `json:"endpoint_index"`
	ConnectedAt     time.Time `json:"connected_at"`
	EndedAt         time.Time `json:"ended_at,omitzero"`
	Code            ErrorCode `json:"code,omitempty"`
	CleanupFailed   bool      `json:"cleanup_failed,omitempty"`
	PacketsSent     uint64    `json:"packets_sent"`
	BytesSent       uint64    `json:"bytes_sent"`
	PacketsReceived uint64    `json:"packets_received"`
	BytesReceived   uint64    `json:"bytes_received"`
}

// GenerationReports returns up to 64 completed generations and the active
// snapshot, if any, newer than afterGeneration. Advance the exclusive
// cursor only from a record with a nonzero EndedAt. Polling with the ID of
// an active snapshot would skip that connection's final record.
func (c *Client) GenerationReports(afterGeneration uint64) []GenerationReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	active := c.liveConnection()
	var reports []GenerationReport
	if c.generations != nil {
		reports = c.generations.After(afterGeneration)
	}
	if active != nil && active.generation > afterGeneration {
		reports = append(reports, generationReport(active))
	}
	return reports
}

// CompletedGenerationReports returns only finalized generations newer than
// the exclusive cursor. A gap can indicate eviction from the 64-record history.
func (c *Client) CompletedGenerationReports(afterGeneration uint64) []GenerationReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.liveConnection()
	if c.generations == nil {
		return nil
	}
	return c.generations.After(afterGeneration)
}

// RekeyReports returns up to 64 retained soft resets from completed
// connections followed by up to eight attempts from a live or closing connection.
func (c *Client) RekeyReports() []RekeyReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.liveConnection()
	var reports []RekeyReport
	if c.rekeys != nil {
		reports = c.rekeys.After(0)
	}
	if tracked := c.observedConnection(); tracked != nil {
		reports = appendRekeyReports(reports, tracked)
	}
	return reports
}

// observedConnection is used for telemetry under c.mu, after liveConnection
// has finalized any standalone generation whose teardown already completed.
func (c *Client) observedConnection() *connection {
	if c.active != nil {
		return c.active
	}
	return c.closing
}

func (c *Client) finishGeneration(active *connection, code ErrorCode) {
	report := generationReport(active)
	report.EndedAt, report.Code = time.Now(), code
	raw, inbound := connectionQueues(active)
	mergeQueue(&c.stats.CiphertextQueue, raw)
	mergeQueue(&c.stats.InboundQueue, inbound)
	if c.closing == active {
		c.closing = nil
	}
	if c.generations == nil {
		c.generations = new(observability.History[GenerationReport])
	}
	c.generations.Append(report)
	for _, rekey := range appendRekeyReports(nil, active) {
		if c.rekeys == nil {
			c.rekeys = new(observability.History[RekeyReport])
		}
		c.rekeys.Append(rekey)
	}
}

func generationReport(active *connection) GenerationReport {
	out := GenerationReport{Generation: active.generation, EndpointIndex: active.index, ConnectedAt: active.started,
		CleanupFailed: active.cleanupFailed}
	out.PacketsSent, out.BytesSent = active.sent.Load()
	out.PacketsReceived, out.BytesReceived = active.recv.Load()
	return out
}

func appendRekeyReports(reports []RekeyReport, active *connection) []RekeyReport {
	if reporter, ok := active.link.(interface{ RekeyResults() []session.RekeyResult }); ok {
		for _, result := range reporter.RekeyResults() {
			report := RekeyReport{Generation: active.generation, KeyID: result.KeyID, PeerInitiated: result.PeerInitiated,
				Started: result.Started, Duration: result.Duration, Phase: result.Phase}
			if result.Err != nil {
				report.Code = packetErrorCode(result.Err, CodeProtocol)
			}
			reports = append(reports, report)
		}
	}
	return reports
}

func connectionQueues(active *connection) (observability.QueueStats, observability.QueueStats) {
	if reporter, ok := active.link.(interface {
		QueueStats() (observability.QueueStats, observability.QueueStats)
	}); ok {
		return reporter.QueueStats()
	}
	return observability.QueueStats{}, observability.QueueStats{}
}

func mergeQueue(dst *QueueStats, snapshot observability.QueueStats) {
	dst.Dropped += snapshot.Dropped
	dst.HighWater = max(dst.HighWater, snapshot.HighWater)
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
			code := packetErrorCode(link.Err(), CodeNetwork)
			if cleanup, ok := link.(interface{ CleanupError() error }); ok && failedCleanup(cleanup.CleanupError()) {
				active.cleanupFailed, c.cleanupFailed = true, true
				if canRetry(code) {
					code = CodeCleanup
				}
			}
			c.disconnected(active, code)
		}
		return nil
	default:
		return active
	}
}
