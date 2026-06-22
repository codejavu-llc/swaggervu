package textutil

import "testing"

func TestSimilarity(t *testing.T) {
	if s := Similarity("hello world", "hello world"); s != 1.0 {
		t.Errorf("identical strings should be 1.0, got %v", s)
	}
	if s := Similarity("the quick brown fox", "completely different!!"); s > 0.5 {
		t.Errorf("dissimilar strings should be low, got %v", s)
	}
	near := Similarity("404 page not found here", "404 page not found there")
	if near < 0.7 {
		t.Errorf("near-identical strings should be high, got %v", near)
	}
	if s := Similarity("", ""); s != 1.0 {
		t.Errorf("two empty strings are identical, got %v", s)
	}
	if s := Similarity("a", "b"); s != 0 {
		t.Errorf("too-short distinct strings should be 0, got %v", s)
	}
}
