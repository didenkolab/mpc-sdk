package threshold

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestInMemoryTransportDelivery(t *testing.T) {
	tr := NewInMemoryTransport()
	const session = "s"

	p2p := Message{FromPartyID: 0, ToPartyID: 1, Round: 1, Data: json.RawMessage(`{"p2p":true}`)}
	bc := Message{FromPartyID: 1, ToPartyID: BroadcastPartyID, Round: 1, Data: json.RawMessage(`{"bc":true}`)}
	if err := tr.SendMessage(session, 1, 1, p2p); err != nil {
		t.Fatal(err)
	}
	if err := tr.BroadcastMessage(session, 1, bc); err != nil {
		t.Fatal(err)
	}

	got, err := tr.ReceiveMessages(session, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d messages, want 2", len(got))
	}
	// Broadcasts come first.
	if string(got[0].Data) != `{"bc":true}` || string(got[1].Data) != `{"p2p":true}` {
		t.Fatalf("unexpected messages %+v", got)
	}

	all := tr.GetAllMessages(session)
	if len(all[1][1]) != 1 || len(all[1][BroadcastPartyID]) != 1 {
		t.Fatalf("GetAllMessages = %+v", all)
	}
	all[1][1][0].FromPartyID = 99 // must be a copy
	if tr.GetAllMessages(session)[1][1][0].FromPartyID != 0 {
		t.Fatal("GetAllMessages exposed internal state")
	}
	if tr.GetAllMessages("unknown") != nil {
		t.Fatal("unknown session must have no messages")
	}

	tr.ClearSession(session)
	if tr.GetAllMessages(session) != nil {
		t.Fatal("ClearSession left messages behind")
	}
}

func TestInMemoryTransportTimeout(t *testing.T) {
	tr := NewInMemoryTransport()
	tr.SetTimeout(100 * time.Millisecond)
	start := time.Now()
	if _, err := tr.ReceiveMessages("s", 1, 1); err == nil {
		t.Fatal("expected timeout")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
}

func TestInMemoryTransportConcurrentSenders(t *testing.T) {
	tr := NewInMemoryTransport()
	tr.SetTimeout(5 * time.Second)
	const senders, perSender = 4, 25

	var wg sync.WaitGroup
	for from := range senders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perSender {
				msg := Message{
					FromPartyID: uint8(from),
					ToPartyID:   uint8((from + 1) % senders),
					Data:        json.RawMessage(fmt.Sprintf(`{"seq":%d}`, i)),
				}
				if err := tr.SendMessage("s", 1, msg.ToPartyID, msg); err != nil {
					t.Error(err)
				}
			}
		}()
	}

	got, err := tr.ReceiveMessages("s", 1, senders*perSender)
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if len(got) != senders*perSender {
		t.Fatalf("got %d messages, want %d", len(got), senders*perSender)
	}
}

func TestMessageJSONRoundTrip(t *testing.T) {
	in := Message{
		FromPartyID: 2,
		ToPartyID:   BroadcastPartyID,
		Round:       int(Round4),
		Data:        json.RawMessage(`{"k":[1,2,3]}`),
		Timestamp:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Message
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.FromPartyID != in.FromPartyID || out.ToPartyID != in.ToPartyID || out.Round != in.Round ||
		string(out.Data) != string(in.Data) || !out.Timestamp.Equal(in.Timestamp) {
		t.Fatalf("round trip mismatch: %+v vs %+v", out, in)
	}
}

func BenchmarkInMemoryTransportSend(b *testing.B) {
	tr := NewInMemoryTransport()
	msg := Message{FromPartyID: 0, ToPartyID: 1, Round: 1, Data: json.RawMessage(`{}`)}
	for b.Loop() {
		if err := tr.SendMessage("bench", 1, 1, msg); err != nil {
			b.Fatal(err)
		}
	}
}
