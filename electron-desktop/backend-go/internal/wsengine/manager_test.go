package wsengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/regaan/wshawk/electron-desktop/backend-go/internal/store"
)

func TestConnectTextBinaryCaptureAndDisconnect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{"wshawk-test"}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		for {
			kind, payload, readErr := connection.Read(request.Context())
			if readErr != nil {
				return
			}
			if writeErr := connection.Write(request.Context(), kind, payload); writeErr != nil {
				return
			}
		}
	}))
	defer server.Close()
	database, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	project, _ := database.SaveProject(context.Background(), store.Project{Name: "ws lab"})
	var mu sync.Mutex
	events := []string{}
	manager := New(database, func(name string, _ any) { mu.Lock(); events = append(events, name); mu.Unlock() })
	defer manager.Close()
	target := "ws" + strings.TrimPrefix(server.URL, "http")
	connected, err := manager.Connect(context.Background(), ConnectOptions{ProjectID: project.ID, URL: target, Subprotocols: []string{"wshawk-test"}})
	if err != nil {
		t.Fatal(err)
	}
	id := connected["connection_id"].(string)
	if connected["subprotocol"] != "wshawk-test" {
		t.Fatalf("subprotocol missing: %#v", connected)
	}
	if _, err := manager.Send(context.Background(), SendOptions{ConnectionID: id, MessageType: "text", Payload: "hello"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		frames, _ := database.ListEntities(context.Background(), "ws_frames", project.ID, 10)
		if len(frames) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	frames, _ := database.ListEntities(context.Background(), "ws_frames", project.ID, 10)
	if len(frames) < 2 {
		t.Fatalf("expected outbound and inbound frames: %#v", frames)
	}
	probeContext, cancelProbe := context.WithTimeout(context.Background(), 2*time.Second)
	probe, err := manager.Probe(probeContext, SendOptions{ConnectionID: id, MessageType: "text", Payload: "probe"})
	cancelProbe()
	if err != nil || probe["response"].(map[string]any)["payload"] != "probe" {
		t.Fatalf("probe failed: %#v %v", probe, err)
	}
	raceContext, cancelRace := context.WithTimeout(context.Background(), 2*time.Second)
	race, err := manager.Race(raceContext, SendOptions{ConnectionID: id, MessageType: "text", Payload: "race"}, 3)
	cancelRace()
	if err != nil || race["received"] != 3 {
		t.Fatalf("race failed: %#v %v", race, err)
	}
	if err := manager.Disconnect(id); err != nil {
		t.Fatal(err)
	}
}
