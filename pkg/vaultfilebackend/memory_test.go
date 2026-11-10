package vaultfilebackend

import (
	"context"
	"errors"
	"testing"
)

func memoryOpen(t *testing.T) Backend { return NewMemory() }

func TestMemoryConformance(t *testing.T) {
	RunConformance(t, memoryOpen, nil)
}

func TestMemoryTokensFollowBytesNotWrites(t *testing.T) {
	ctx := context.Background()
	b := NewMemory()
	if err := b.CreateIfAbsent(ctx, "a", []byte("same")); err != nil {
		t.Fatal(err)
	}
	if err := b.CreateIfAbsent(ctx, "b", []byte("same")); err != nil {
		t.Fatal(err)
	}
	a, _ := b.Read(ctx, "a")
	c, _ := b.Read(ctx, "b")
	if a.Token != c.Token {
		t.Fatal("equal bytes must produce equal tokens")
	}
	if err := b.CreateIfAbsent(ctx, "c", []byte("diff")); err != nil {
		t.Fatal(err)
	}
	d, _ := b.Read(ctx, "c")
	if d.Token == a.Token {
		t.Fatal("different bytes must produce different tokens")
	}
}

func TestMemoryCancellationKeepsCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := NewMemory().CreateIfAbsent(ctx, "n", []byte("v"))
	if !errors.Is(err, ErrDenied) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled = %v, want ErrDenied wrapping context.Canceled", err)
	}
}
