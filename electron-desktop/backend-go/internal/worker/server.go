package worker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/certutil"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/protocol"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/reporting"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/scanner"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/store"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/websec"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/wsengine"
)

const backendVersion = "4.0.3"

type Handler func(json.RawMessage) (any, *protocol.RPCError)

type Server struct {
	input         io.Reader
	output        io.Writer
	diagnostics   io.Writer
	handlers      map[string]Handler
	shutdown      atomic.Bool
	store         *store.Store
	websockets    *wsengine.Manager
	web           *websec.Client
	scanner       *scanner.Engine
	reports       *reporting.Generator
	outputMu      sync.Mutex
	operationMu   sync.Mutex
	operations    map[string]*trackedOperation
	events        chan eventEnvelope
	done          chan struct{}
	closeOnce     sync.Once
	dropped       atomic.Uint64
	certificateMu sync.Mutex
	certificateCA *certutil.Pair
}

type eventEnvelope struct {
	Version   string `json:"version"`
	Event     string `json:"event"`
	Data      any    `json:"data"`
	Timestamp string `json:"timestamp"`
}

func NewServer(input io.Reader, output io.Writer, diagnostics io.Writer) *Server {
	database, err := store.OpenMemory()
	if err != nil {
		panic(fmt.Sprintf("open worker test store: %v", err))
	}
	return newServer(input, output, diagnostics, database)
}

func NewServerWithDataDir(input io.Reader, output io.Writer, diagnostics io.Writer, dataDir string) (*Server, error) {
	database, err := store.Open(dataDir)
	if err != nil {
		return nil, err
	}
	return newServer(input, output, diagnostics, database), nil
}

func newServer(input io.Reader, output io.Writer, diagnostics io.Writer, database *store.Store) *Server {
	server := &Server{
		input:       input,
		output:      output,
		diagnostics: diagnostics,
		handlers:    make(map[string]Handler),
		store:       database,
		operations:  make(map[string]*trackedOperation),
		events:      make(chan eventEnvelope, 256),
		done:        make(chan struct{}),
	}
	server.websockets = wsengine.New(database, server.emit)
	server.web = websec.New(database)
	server.scanner = scanner.New(server.web, database, server.emit)
	server.reports = reporting.New(database)
	server.handlers["system.health"] = server.health
	server.handlers["system.capabilities"] = server.capabilities
	server.handlers["system.shutdown"] = server.requestShutdown
	server.registerStorageHandlers()
	server.registerWebSocketHandlers()
	server.registerWebHandlers()
	server.registerScannerHandlers()
	server.registerReportHandlers()
	server.registerNetworkHandlers()
	server.registerWorkflowHandlers()
	go server.eventPump()
	return server
}

func (s *Server) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.cancelAllOperations()
		if s.scanner != nil {
			s.scanner.Close()
		}
		if s.websockets != nil {
			s.websockets.Close()
		}
		close(s.done)
		if s.store != nil {
			closeErr = s.store.Close()
		}
	})
	return closeErr
}

func (s *Server) Run() int {
	defer s.Close()
	scanner := bufio.NewScanner(s.input)
	scanner.Buffer(make([]byte, 64*1024), protocol.MaxRequestBytes)
	var requests sync.WaitGroup

	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		var envelope protocol.Request
		_ = json.Unmarshal(line, &envelope)
		if strings.HasPrefix(envelope.Method, "system.") {
			s.writeResponse(s.handleLine(line))
			if envelope.Method == "system.shutdown" {
				requests.Wait()
				return 0
			}
			continue
		}
		requests.Add(1)
		go func() { defer requests.Done(); s.writeResponse(s.handleLine(line)) }()
	}
	requests.Wait()

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(s.diagnostics, "worker input failure: %v\n", err)
		return 1
	}
	return 0
}

func (s *Server) writeResponse(response protocol.Response) {
	encoded, err := protocol.EncodeResponse(response)
	if err != nil {
		fmt.Fprintf(s.diagnostics, "worker response encoding failure: %v\n", err)
		return
	}
	if err := s.writeLine(encoded); err != nil {
		fmt.Fprintf(s.diagnostics, "worker response write failure: %v\n", err)
	}
}

func (s *Server) writeLine(encoded []byte) error {
	s.outputMu.Lock()
	defer s.outputMu.Unlock()
	_, err := s.output.Write(append(encoded, '\n'))
	return err
}

func (s *Server) emit(name string, data any) {
	event := eventEnvelope{Version: protocol.Version, Event: name, Data: data, Timestamp: time.Now().UTC().Format(time.RFC3339Nano)}
	select {
	case <-s.done:
		return
	default:
	}
	select {
	case s.events <- event:
	default:
		s.dropped.Add(1)
	}
}

func (s *Server) eventPump() {
	for {
		select {
		case <-s.done:
			return
		case event := <-s.events:
			encoded, err := json.Marshal(event)
			if err != nil {
				continue
			}
			if err := s.writeLine(encoded); err != nil {
				fmt.Fprintf(s.diagnostics, "worker event write failure: %v\n", err)
				return
			}
		}
	}
}

func (s *Server) handleLine(line []byte) protocol.Response {
	request, rpcError := protocol.DecodeRequest(line)
	if rpcError != nil {
		return protocol.Failure(request.ID, rpcError)
	}
	handler, ok := s.handlers[request.Method]
	if !ok {
		return protocol.Failure(request.ID, &protocol.RPCError{
			Code:    "method_not_found",
			Message: "Worker method is not supported",
		})
	}
	result, rpcError := handler(request.Params)
	if rpcError != nil {
		return protocol.Failure(request.ID, rpcError)
	}
	return protocol.Success(request.ID, result)
}

func (s *Server) health(_ json.RawMessage) (any, *protocol.RPCError) {
	database := s.store.Health(context.Background())
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return map[string]any{
		"status":          "ready",
		"backend":         "go",
		"version":         backendVersion,
		"goVersion":       runtime.Version(),
		"pid":             os.Getpid(),
		"transport":       "stdio-json-rpc",
		"noNetworkBridge": true,
		"database":        database,
		"droppedEvents":   s.dropped.Load(),
		"memory": map[string]any{
			"allocatedBytes": memory.Alloc,
			"heapInUseBytes": memory.HeapInuse,
			"systemBytes":    memory.Sys,
			"goroutines":     runtime.NumGoroutine(),
		},
	}, nil
}

func (s *Server) capabilities(_ json.RawMessage) (any, *protocol.RPCError) {
	methods := make([]string, 0, len(s.handlers))
	for method := range s.handlers {
		methods = append(methods, method)
	}
	sort.Strings(methods)
	return map[string]any{
		"protocolVersion": protocol.Version,
		"backendVersion":  backendVersion,
		"methods":         methods,
		"eventStreaming":  true,
		"cancellation":    true,
	}, nil
}

func (s *Server) requestShutdown(_ json.RawMessage) (any, *protocol.RPCError) {
	s.shutdown.Store(true)
	if s.scanner != nil {
		s.scanner.Close()
	}
	return map[string]any{"accepted": true}, nil
}
