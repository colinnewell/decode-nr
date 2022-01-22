package connections

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/colinnewell/decode-nr/protocol"
	"github.com/colinnewell/pcap-cli/general"
	"github.com/colinnewell/pcap-cli/tcp"
	flatbuffers "github.com/google/flatbuffers/go"
)

const (
	bothSides = 2
	maxSize   = 2 << 20 /* 2Mb */

	binaryType = 2
)

type NRConnection struct {
	Address        string    `json:"address,omitempty"`
	ClientMessages []Message `json:"client_messages,omitempty"`
	ServerMessages []Message `json:"server_messages,omitempty"`
}

type Message struct {
	AgentLanguage             string           `json:"agent_language,omitempty"`
	AgentVersion              string           `json:"agent_version,omitempty"`
	AppName                   string           `json:"app_name,omitempty"`
	Data                      []byte           `json:"data,omitempty"`
	DisplayHost               string           `json:"display_host,omitempty"`
	Environment               string           `json:"environment,omitempty"`
	Host                      string           `json:"host,omitempty"`
	Labels                    string           `json:"labels,omitempty"`
	License                   string           `json:"license,omitempty"`
	RedirectCollector         string           `json:"redirect_collector,omitempty"`
	SecurityPolicyToken       string           `json:"security_policy_token,omitempty"`
	SupportedSecurityPolicies *json.RawMessage `json:"supported_security_policies,omitempty"`
	Type                      string           `json:"type,omitempty"`
	Error                     string           `json:"error,omitempty"`
	AgentRunID                string           `json:"agent_run_id,omitempty"`
	ReplyStatus               string           `json:"reply_status,omitempty"`
	MetricsLength             int              `json:"metrics_length,omitempty"`
	CustomEventsLength        int              `json:"custom_events_length,omitempty"`
	SpanEventsLength          int              `json:"span_events_length,omitempty"`
	ErrorEventsLength         int              `json:"error_events_length,omitempty"`
	TransactionName           string           `json:"transaction_name,omitempty"`
	URI                       string           `json:"uri,omitempty"`
	SlowSQLsLength            int              `json:"slow_sq_ls_length,omitempty"`
	PID                       int32            `json:"pid,omitempty"`
	SyntheticsResourceID      string           `json:"synthetics_resource_id,omitempty"`
	TxnEvent                  *json.RawMessage `json:"txn_event,omitempty"`
	Metrics                   []Metric         `json:"metrics,omitempty"`
	Errors                    []Error          `json:"errors,omitempty"`
	SlowSQL                   []SlowSQL        `json:"slow_sql,omitempty"`
	UnixTimestampMillis       float64          `json:"unix_timestamp_millis,omitempty"`
	DurationMillis            float64          `json:"duration_millis,omitempty"`
	GUID                      string           `json:"guid,omitempty"`
	TraceData                 *json.RawMessage `json:"trace_data,omitempty"`
	ForcePersist              bool             `json:"force_persist,omitempty"`
	ConnectReply              *json.RawMessage `json:"connect_reply,omitempty"`
	ConnectTimestamp          uint64           `json:"connect_timestamp,omitempty"`
	HarvestFrequency          uint16           `json:"harvest_frequency,omitempty"`
	SamplingTarget            uint16           `json:"sampling_target,omitempty"`
	SecurityPolicies          *json.RawMessage `json:"security_policies,omitempty"`
}

type Error struct {
	Priority int32  `json:"priority,omitempty"`
	Data     string `json:"data,omitempty"`
}

type SlowSQL struct {
	ID          uint32 `json:"id,omitempty"`
	Count       int32  `json:"count,omitempty"`
	TotalMicros uint64 `json:"total_micros,omitempty"`
	MinMicros   uint64 `json:"min_micros,omitempty"`
	MaxMicros   uint64 `json:"max_micros,omitempty"`
	MetricName  string `json:"metric_name,omitempty"`
	Query       string `json:"query,omitempty"`
	Params      string `json:"params,omitempty"`
}

type Metric struct {
	Name       string  `json:"name,omitempty"`
	Count      float64 `json:"count,omitempty"`
	Total      float64 `json:"total,omitempty"`
	Exclusive  float64 `json:"exclusive,omitempty"`
	Min        float64 `json:"min,omitempty"`
	Max        float64 `json:"max,omitempty"`
	SumSquares float64 `json:"sum_squares,omitempty"`
	Forced     bool    `json:"forced,omitempty"`
	Scoped     bool    `json:"scoped,omitempty"`
}

type Header struct {
	Size uint32
	Type uint32
}

type NRConnectionBuilder struct {
	address       tcp.ConnectionAddress
	completed     chan interface{}
	sidesComplete uint8
	mu            sync.Mutex
	con           NRConnection
}

func (b *NRConnectionBuilder) ReadClientStream(s *tcp.TimeCaptureReader) error {
	return b.readStream(s, &b.con.ClientMessages)
}

func (b *NRConnectionBuilder) ReadServerStream(s *tcp.TimeCaptureReader) error {
	return b.readStream(s, &b.con.ServerMessages)
}

func (b *NRConnectionBuilder) readStream(s *tcp.TimeCaptureReader, messages *[]Message) error {
	for {
		err := b.readMessage(s, messages)
		if err != nil {
			return err
		}
	}
}

func (b *NRConnectionBuilder) readMessage(s *tcp.TimeCaptureReader, messages *[]Message) error {
	hdr := Header{}
	if err := binary.Read(s, binary.LittleEndian, &hdr); err != nil {
		return fmt.Errorf("client header read: %w", err)
	}
	if hdr.Size > maxSize {
		return fmt.Errorf("reported data size too large")
	}
	if hdr.Type != binaryType {
		return fmt.Errorf("unexpected type")
	}
	msg := make([]byte, hdr.Size)
	if _, err := io.ReadFull(s, msg); err != nil {
		return fmt.Errorf("message read fail: %w", err)
	}

	if len(msg) == 0 {
		return fmt.Errorf("empty message")
	}

	m := protocol.GetRootAsMessage(msg, 0)
	message := Message{
		Type: m.DataType().String(),
	}
	flatbuffers.NewBuilder(0)
	switch m.DataType() {
	case protocol.MessageBodyAppReply:
		decodeReply(&message, m)
	case protocol.MessageBodyNONE:
	case protocol.MessageBodyTransaction:
		readTransaction(&message, m)
	case protocol.MessageBodyApp:
		readApp(&message, m)
	}
	*messages = append(*messages, message)

	return nil
}

func decodeReply(msg *Message, pm *protocol.Message) {
	var tbl flatbuffers.Table

	if !pm.Data(&tbl) {
		return
	}

	var reply protocol.AppReply

	reply.Init(tbl.Bytes, tbl.Pos)
	msg.ReplyStatus = reply.Status().String()
	msg.ConnectReply = jsonPtr(reply.ConnectReply())
	msg.SecurityPolicies = jsonPtr(reply.SecurityPolicies())
	msg.ConnectTimestamp = reply.ConnectTimestamp()
	msg.SamplingTarget = reply.SamplingTarget()
}

func jsonPtr(b []byte) *json.RawMessage {
	if len(b) == 0 {
		return nil
	}
	m := make([]byte, len(b))
	copy(m, b)
	j := json.RawMessage(m)
	return &j
}

func readApp(msg *Message, pm *protocol.Message) {
	var tbl flatbuffers.Table

	if !pm.Data(&tbl) {
		return
	}

	var app protocol.App

	app.Init(tbl.Bytes, tbl.Pos)

	msg.License = string(app.License())
	msg.AppName = string(app.AppName())
	msg.AgentLanguage = string(app.AgentLanguage())
	msg.AgentVersion = string(app.AgentVersion())
	msg.RedirectCollector = string(app.RedirectCollector())
	msg.Environment = string(app.Environment())
	msg.Labels = string(app.Labels())
	msg.Host = string(app.Host())
	msg.DisplayHost = string(app.DisplayHost())
	msg.SecurityPolicyToken = string(app.SecurityPolicyToken())
	msg.SupportedSecurityPolicies = jsonPtr(app.SupportedSecurityPolicies())
}

func readTransaction(msg *Message, pm *protocol.Message) {
	var tbl flatbuffers.Table

	if !pm.Data(&tbl) {
		msg.Error = "missing agent run id for txn data command"
		return
	}

	id := pm.AgentRunId()
	if len(id) == 0 {
		msg.Error = "missing agent run id for txn data command"
		return
	}
	msg.AgentRunID = string(id)
	var txn protocol.Transaction
	txn.Init(tbl.Bytes, tbl.Pos)
	msg.MetricsLength = txn.MetricsLength()
	msg.CustomEventsLength = txn.CustomEventsLength()
	msg.SpanEventsLength = txn.SpanEventsLength()
	msg.ErrorEventsLength = txn.ErrorEventsLength()
	msg.SlowSQLsLength = txn.SlowSqlsLength()
	msg.TransactionName = string(txn.Name())
	msg.URI = string(txn.Uri())
	msg.PID = txn.Pid()
	if x := txn.SyntheticsResourceId(); len(x) > 0 {
		msg.SyntheticsResourceID = string(x)
	}
	if event := txn.TxnEvent(nil); event != nil {
		msg.TxnEvent = jsonPtr(event.Data())
	}
	// check for events
	// errors etc.
	msg.Metrics = GrabMetrics(txn)
	msg.Errors = GrabErrors(txn)
	msg.SlowSQL = GrabSlowSQL(txn)

	if trace := txn.Trace(nil); trace != nil {
		data := trace.Data()
		msg.UnixTimestampMillis = trace.Timestamp()
		msg.DurationMillis = trace.Duration()
		msg.GUID = string(trace.Guid())
		msg.ForcePersist = trace.ForcePersist()
		msg.TraceData = jsonPtr(data)
	}
}

func GrabErrors(txn protocol.Transaction) []Error {
	var errors []Error
	if n := txn.ErrorsLength(); n > 0 {
		var e protocol.Error
		for i := 0; i < n; i++ {
			txn.Errors(&e, i)

			errors = append(errors, Error{
				Priority: e.Priority(),
				Data:     string(e.Data()),
			})
		}
	}
	return errors
}

func GrabSlowSQL(txn protocol.Transaction) []SlowSQL {
	var list []SlowSQL
	if n := txn.SlowSqlsLength(); n > 0 {
		var slowSQL protocol.SlowSQL

		for i := 0; i < n; i++ {
			txn.SlowSqls(&slowSQL, i)

			slow := SlowSQL{}
			slow.ID = slowSQL.Id()
			slow.Count = slowSQL.Count()
			slow.TotalMicros = slowSQL.TotalMicros()
			slow.MinMicros = slowSQL.MinMicros()
			slow.MaxMicros = slowSQL.MaxMicros()

			slow.MetricName = string(slowSQL.Metric())
			slow.Query = string(slowSQL.Query())
			slow.Params = string(slowSQL.Params())

			list = append(list, slow)
		}
	}
	return list
}

func GrabMetrics(txn protocol.Transaction) []Metric {
	var m protocol.Metric
	var data protocol.MetricData
	n := txn.MetricsLength()
	var metrics []Metric
	for i := 0; i < n; i++ {
		var metric Metric
		txn.Metrics(&m, i)
		m.Data(&data)

		metric.Count = data.Count()
		metric.Total = data.Total()
		metric.Exclusive = data.Exclusive()
		metric.Min = data.Min()
		metric.Max = data.Max()
		metric.SumSquares = data.SumSquares()
		metric.Forced = data.Forced()
		metric.Scoped = data.Scoped()
		metric.Name = string(m.Name())
		metrics = append(metrics, metric)
	}

	return metrics
}

func (b *NRConnectionBuilder) ReadDone() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sidesComplete++
	if b.sidesComplete == bothSides {
		b.con.Address = b.address.String()
		b.completed <- &b.con
	}
}

type NRConnectionBuilderFactory struct{}

func (f *NRConnectionBuilderFactory) NewBuilder(address tcp.ConnectionAddress, completed chan interface{}) general.ConnectionBuilder {
	return &NRConnectionBuilder{
		address:   address,
		completed: completed,
		con: NRConnection{
			ClientMessages: []Message{},
			ServerMessages: []Message{},
		},
	}
}
