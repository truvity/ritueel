package trustset_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/cli"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/trustset"
)

// threeSets makes a chain of a first list, a renewal and a revoke, in the order a bundle grows.
func threeSets(t *testing.T) *chain {
	t.Helper()
	c := newChain(t)
	c.add(next{labels: []string{"A", "B"}})
	c.add(next{labels: []string{"A", "B"}})
	c.add(next{labels: []string{"B"}, deps: []trustset.Departure{revoke(t, "A")}})
	return c
}

// A bundle made by bundle.Create, a set written by Set.Write under trust/<number>-<eight digits>, and
// read back by bundle.Open and Bundle.Roots: the three file names and the spelling of the name
// agree with internal/bundle.
func TestRoundTripWithTheBundle(t *testing.T) {
	c := threeSets(t)
	dir := filepath.Join(t.TempDir(), "acme")
	if _, err := bundle.Create(dir, bundle.StarterOptions{TestRoot: true}); err != nil {
		t.Fatal(err)
	}
	w, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	if err := w.Mkdir(bundle.TrustDir, 0o700); err != nil {
		t.Fatal(err)
	}
	wantLabels := [][]string{{"A", "B"}, {"A", "B"}, {"B"}}
	for i, l := range c.links {
		name, err := trustset.SetName(l.set.Sequence(), l.draft.ListSHA256())
		if err != nil {
			t.Fatal(err)
		}
		if err := l.set.Write(w, bundle.TrustDir+"/"+name); err != nil {
			t.Fatalf("Write %d: %v", i+1, err)
		}
		b, err := bundle.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		refs, set, err := b.Roots()
		_ = b.Close()
		if err != nil {
			t.Fatalf("Roots after set %d: %v", i+1, err)
		}
		if set.Name != name || set.Number != int64(i+1) {
			t.Errorf("the newest set is %+v, want %s", set, name)
		}
		if len(refs) != len(wantLabels[i]) {
			t.Fatalf("set %d: %d roots", i+1, len(refs))
		}
		for j, label := range wantLabels[i] {
			cert := newRoot(t, label, true).Cert
			if !bytes.Equal(refs[j].Subject, cert.RawSubject) {
				t.Errorf("set %d root %d is not the key %s", i+1, j, label)
			}
		}
	}
}

// The root lists of the written sets pass the reader of the history through FindReturns, with Earlier
// made from the files read back, and no return is found; a key that left and is asked for again is.
func TestWrittenSetsHaveNoReturns(t *testing.T) {
	c := threeSets(t)
	var earlier []history.RootList
	for i, l := range c.links {
		list, err := rootlist.ParseList(l.set.ListJSON())
		if err != nil {
			t.Fatal(err)
		}
		cur := history.RootList{Name: "now"}
		for _, r := range list.Roots {
			cur.Keys = append(cur.Keys, history.RootKey{Label: r.Label, Pin: r.X509SPKISHA256, Fingerprint: r.OpenPGPFingerprint})
		}
		found, err := history.FindReturns(earlier, cur)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 0 {
			t.Errorf("list %d: %+v", i+1, found)
		}
		earlier = append(earlier, history.RootList{Name: "set", Keys: cur.Keys})
	}
	// The key that left is a return, by the reader of the history as well as by the builder.
	back := history.RootList{Name: "again", Keys: []history.RootKey{
		{Label: "A", Pin: newRoot(t, "A", true).Pin, Fingerprint: newRoot(t, "A", true).Print},
		{Label: "B", Pin: newRoot(t, "B", true).Pin, Fingerprint: newRoot(t, "B", true).Print},
	}}
	found, err := history.FindReturns(earlier, back)
	if err != nil || len(found) != 1 || found[0].Entry != 0 || !found[0].ByPin {
		t.Errorf("the reader of the history says %+v, %v", found, err)
	}
	if _, err := c.draft(next{labels: []string{"A", "B"}}); err == nil {
		t.Error("the builder takes the key that left")
	}
}

// The command verify root-list reads what the builder wrote: the written folders pass with exit code
// 0, against the held list for a later list and with the initial pins for the first one.
func TestVerifyRootListAcceptsTheWrittenFolders(t *testing.T) {
	c := threeSets(t)
	root := t.TempDir()
	dirs := make([]string, len(c.links))
	for i, l := range c.links {
		dirs[i] = filepath.Join(root, strings.Repeat("s", i+1))
		if err := os.Mkdir(dirs[i], 0o755); err != nil {
			t.Fatal(err)
		}
		for _, f := range l.set.Files() {
			if err := os.WriteFile(filepath.Join(dirs[i], f.Name), f.Data, f.Perm); err != nil {
				t.Fatal(err)
			}
		}
	}
	run := func(now time.Time, args ...string) (cli.ExitCode, string, string) {
		var out, errOut bytes.Buffer
		code := cli.Run(context.Background(), args, cli.Env{Stdout: &out, Stderr: &errOut, Now: func() time.Time { return now }})
		return code, out.String(), errOut.String()
	}
	for i, l := range c.links {
		args := []string{"--output", "json", "verify", "root-list", filepath.Join(dirs[i], "root-list.json"), "--ca-bundle", filepath.Join(dirs[i], "ca-bundle.pem")}
		if i == 0 {
			list, err := rootlist.ParseList(l.set.ListJSON())
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range list.Pins() {
				args = append(args, "--pin", p)
			}
		} else {
			args = append(args, "--held", filepath.Join(dirs[i-1], "root-list.json"))
		}
		code, out, errOut := run(l.signed, args...)
		if code != cli.ExitOK {
			t.Fatalf("set %d: exit code %d\n%s\n%s", i+1, code, out, errOut)
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(out), &obj); err != nil {
			t.Fatalf("set %d: %v\n%s", i+1, err, out)
		}
		if obj["outcome"] != "done" || obj["exit_code"] != float64(0) {
			t.Errorf("set %d: %s", i+1, out)
		}
		// The command names the digests of the three files it read: the digests of the set.
		for _, want := range []string{hexOf(string(l.set.ListJSON())), hexOf(string(l.set.ListJWS())), hexOf(string(l.set.CABundle()))} {
			if !strings.Contains(out, want) {
				t.Errorf("set %d: the command did not read the file of digest %s: %s", i+1, want, out)
			}
		}
	}
	// A list that was signed in the future of the host's clock is refused by check 5.
	code, _, _ := run(c.links[1].signed.Add(-time.Hour), "verify", "root-list", filepath.Join(dirs[1], "root-list.json"), "--held", filepath.Join(dirs[0], "root-list.json"))
	if code == cli.ExitOK {
		t.Error("a list signed after the clock of the host was taken")
	}
}
