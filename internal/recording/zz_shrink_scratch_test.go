package recording

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestScratchShrink(t *testing.T) {
	src := os.Getenv("PINKY_SHRINK_SRC")
	if src == "" {
		t.Skip()
	}
	dst := src + ".out.mp4"
	start := time.Now()
	if err := Shrink(context.Background(), src, dst, Smaller); err != nil {
		t.Fatal(err)
	}
	a, _ := Probe(src)
	b, _ := Probe(dst)
	sa, _ := os.Stat(src)
	sb, _ := os.Stat(dst)
	t.Logf("took %v", time.Since(start))
	t.Logf("src %+v %d bytes %.2f MB/min", a, sa.Size(), float64(sa.Size())/1e6/a.Length.Minutes())
	t.Logf("dst %+v %d bytes %.2f MB/min", b, sb.Size(), float64(sb.Size())/1e6/b.Length.Minutes())
}
