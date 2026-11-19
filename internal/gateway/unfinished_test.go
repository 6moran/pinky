package gateway

import (
	"context"
	"testing"
	"time"
)

// TestTaskOfAPinkyThatCrashed: a task that ran when Pinky was killed has
// no end in the history. The next Pinky ends it at its last step, as a
// gateway that stopped in order does (failed, "gateway stopped"), so that
// Activity shows no task that runs for ever and Export all has it.
func TestTaskOfAPinkyThatCrashed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	g1, _ := newTestGateway(t, func(o *Options) { o.DataDir = dir })
	s, _ := connect(t, g1, "Lunch")
	mustStatus(t, s.Observe(ctx, ObserveRequest{}), StatusSettled)
	g1.Flush()
	// Killed here: g1 writes nothing more before the next Pinky starts.

	g2, _ := newTestGateway(t, func(o *Options) { o.DataDir = dir })
	stored, err := g2.History(ctx, HistoryQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Fatalf("%d tasks in the history", len(stored))
	}
	task := stored[0]
	if task.State != TaskFailed {
		t.Errorf("state %q, want %q", task.State, TaskFailed)
	}
	if len(task.Steps) == 0 {
		t.Fatal("no steps in the history")
	}
	last := task.Steps[len(task.Steps)-1]
	if want := last.At.Add(last.Elapsed); !task.Ended.Equal(want) {
		t.Errorf("ended %v, want the end of its last step %v", task.Ended, want)
	}
	rec, ok, err := g2.store.Task(ctx, task.ID)
	if err != nil || !ok {
		t.Fatalf("stored task: ok=%v err=%v", ok, err)
	}
	if rec.Outcome != "gateway stopped" {
		t.Errorf("outcome %q, want \"gateway stopped\"", rec.Outcome)
	}
	// Export all leaves out what still runs: this one no longer does.
	out, err := g2.exportTasks(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].ID != task.ID {
		t.Errorf("export all has %d tasks, want this one", len(out))
	}

}

// TestApprovalOfAPinkyThatCrashed: an approval that waited for the person
// when Pinky was killed can no longer be answered. The next Pinky takes it
// back, as a gateway that stopped in order does, so that the task's step
// in Activity does not wait for the person for ever.
func TestApprovalOfAPinkyThatCrashed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	g1, _ := newTestGateway(t, func(o *Options) { o.DataDir = dir; o.MaxBlock = 20 * time.Millisecond })
	s, _ := connect(t, g1, "Lunch")
	mustStatus(t, payInDinely(t, s), StatusPending)
	g1.Flush()
	// Killed here, with the approval open.

	g2, _ := newTestGateway(t, func(o *Options) { o.DataDir = dir })
	stored, err := g2.History(ctx, HistoryQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Fatalf("%d tasks in the history", len(stored))
	}
	task := stored[0]
	last := task.Steps[len(task.Steps)-1]
	if last.Status != "withdrawn" {
		t.Errorf("the approval's step %q has status %q, want withdrawn", last.Text, last.Status)
	}
	aps, err := g2.store.Approvals(ctx, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(aps) != 1 {
		t.Fatalf("%d approvals in the history", len(aps))
	}
	if aps[0].Decision != "withdrawn" || aps[0].Decided.IsZero() {
		t.Errorf("approval: decision %q, decided %v; want withdrawn at a time", aps[0].Decision, aps[0].Decided)
	}
}
