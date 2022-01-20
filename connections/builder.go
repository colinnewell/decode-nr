package connections

import (
	"encoding/binary"
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
	AgentLanguage             string               `json:"agent_language,omitempty"`
	AgentVersion              string               `json:"agent_version,omitempty"`
	AppName                   string               `json:"app_name,omitempty"`
	Data                      []byte               `json:"data,omitempty"`
	DisplayHost               string               `json:"display_host,omitempty"`
	Environment               string               `json:"environment,omitempty"`
	Host                      string               `json:"host,omitempty"`
	Labels                    string               `json:"labels,omitempty"`
	License                   string               `json:"license,omitempty"`
	RedirectCollector         string               `json:"redirect_collector,omitempty"`
	SecurityPolicyToken       string               `json:"security_policy_token,omitempty"`
	SupportedSecurityPolicies string               `json:"supported_security_policies,omitempty"`
	Type                      protocol.MessageBody `json:"type,omitempty"`
	Error                     string               `json:"error,omitempty"`
	AgentRunID                []byte               `json:"agent_run_id,omitempty"`
	TxnData                   []byte               `json:"txn_data,omitempty"`
	MetricsLength             int                  `json:"metrics_length,omitempty"`
	TransactionName           string               `json:"transaction_name,omitempty"`
	URI                       string               `json:"uri,omitempty"`
	SlowSQLsLength            int                  `json:"slow_sq_ls_length,omitempty"`
	PID                       int32                `json:"pid,omitempty"`
	SyntheticsResourceID      string               `json:"synthetics_resource_id,omitempty"`
	TxnEvent                  string               `json:"txn_event,omitempty"`
	Metrics                   []Metric             `json:"metrics,omitempty"`
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
		Type: m.DataType(),
	}
	flatbuffers.NewBuilder(0)
	switch m.DataType() {
	case protocol.MessageBodyAppReply:
	case protocol.MessageBodyNONE:
	case protocol.MessageBodyTransaction:
		readTransaction(&message, m, msg)
	case protocol.MessageBodyApp:
		readApp(&message, m)
	}
	*messages = append(*messages, message)

	return nil
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
	msg.SupportedSecurityPolicies = string(app.SupportedSecurityPolicies())
}

func readTransaction(msg *Message, pm *protocol.Message, data []byte) {
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
	//msg.AgentRunID = id
	var txn protocol.Transaction
	txn.Init(tbl.Bytes, tbl.Pos)
	msg.MetricsLength = txn.MetricsLength()
	msg.SlowSQLsLength = txn.SlowSqlsLength()
	msg.TransactionName = string(txn.Name())
	msg.URI = string(txn.Uri())
	msg.PID = txn.Pid()
	if x := txn.SyntheticsResourceId(); len(x) > 0 {
		msg.SyntheticsResourceID = string(x)
	}
	if event := txn.TxnEvent(nil); event != nil {
		msg.TxnEvent = string(event.Data())
	}
	// check for events
	// errors etc.
	msg.Metrics = GrabMetrics(txn)
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
