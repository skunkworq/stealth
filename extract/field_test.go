package extract

import "testing"

func TestFieldKeyClass(t *testing.T) {
	if ClassOf(KeyABN) != ClassIdentifier {
		t.Fatalf("abn should be identifier, got %v", ClassOf(KeyABN))
	}
	if ClassOf(KeyEmail) != ClassEmail {
		t.Fatalf("email should be email class, got %v", ClassOf(KeyEmail))
	}
	if ClassOf(KeyAddress) != ClassFreeText {
		t.Fatalf("address should be freetext, got %v", ClassOf(KeyAddress))
	}
	if ClassOf(KeyWebsite) != ClassURL {
		t.Fatalf("website should be url, got %v", ClassOf(KeyWebsite))
	}
}
