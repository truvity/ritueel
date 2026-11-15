//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/buildinfo"
	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
)

// The fuzz targets of the readers of untrusted bytes of this part: a saved plan, the wanted files
// and the shape of a bundle, and the words of a plan. No target starts an outside program.

func FuzzReadPlanOut(f *testing.F) {
	golden := []byte(pfGolden)
	f.Add(golden)
	f.Add([]byte(strings.Replace(pfGolden, `"x509/A"`, `"x509/B"`, 1)))
	f.Add([]byte(strings.Replace(pfGolden, `"derived":true`, `"derived":false`, 1)))
	f.Add([]byte(strings.Replace(pfGolden, `"trust_sequence":1`, `"trust_sequence":2`, 1)))
	f.Add([]byte(strings.Replace(pfGolden, `"version":1,`, `"version":1,"touches":0,`, 1)))
	f.Add([]byte(strings.Replace(pfGolden, `"signatures":[`, `"leaves_out":[],"signatures":[`, 1)))
	f.Add(append(append([]byte(nil), golden...), '\n'))
	f.Add(golden[:len(golden)/2])
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(strings.Repeat("[", 5000)))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ceremony.ReadPlanOut(data)
		if err != nil {
			if p != nil {
				t.Fatalf("an error with a plan: %v", err)
			}
			return
		}
		// An accepted file is exactly the canonical bytes of its own reading.
		canon, cerr := p.Plan.Canonical()
		if cerr != nil || !bytes.Equal(canon, data) {
			t.Fatalf("an accepted file is not the canonical bytes of its reading: %v", cerr)
		}
		if !bytes.Equal(p.JSON, data) || p.SHA256 != files.Digest(data) || p.Prefix != p.SHA256[:8] {
			t.Fatal("the bytes or the digest of an accepted plan are not the file")
		}
		if p.Name == "" || len(p.Births) == 0 || len(p.Births) != len(p.Applies) || len(p.Signatures) != 2*len(p.Births)+1 {
			t.Fatalf("an accepted plan has no shape: %+v", p)
		}
		again, err := ceremony.ReadPlanOut(p.JSON)
		if err != nil || !reflect.DeepEqual(again, p) {
			t.Fatalf("a plan read twice: %v", err)
		}
		for _, l := range p.Words() {
			if !pfPrintable(l) {
				t.Fatalf("the words of an accepted plan hold %+q", l)
			}
		}
		// The input is not shared.
		if len(data) > 0 {
			data[0] ^= 1
			if p.JSON[0] == data[0] {
				t.Fatal("the plan shares the bytes of the input")
			}
		}
	})
}

func FuzzFind(f *testing.F) {
	f.Add(pfSettings, pfX509Test, pfX509Test, "acme-ca", byte(0))
	f.Add(pfSettings, pfX509Test, pfX509Test, "acme-ca", byte(1))
	f.Add(pfSettings, pfX509Test, pfOpenPGPTest, "a b", byte(1|2))
	f.Add(pfSettings, pfX509Real, "", ".rt-x", byte(2))
	f.Add(pfPersonal, pfX509Test, "", "", byte(0))
	f.Add(pfSettings, pfX509Test, "version: 1\ntype: x509-intermediate\nroot: x509\npermitted_dns_names: [example.org]\n", "r", byte(32))
	f.Add(pfSettings, pfX509Test, "{}", "r", byte(4))
	f.Add(pfSettings, pfX509Test, "{}", "r", byte(8))
	f.Add(pfSettings, pfX509Test, "{}", "r", byte(16))
	f.Add("", "", "", "", byte(255))
	f.Fuzz(func(t *testing.T, settings, root, other, request string, flags byte) {
		fileSet := map[string]string{"ritueel.yaml": settings, "want/roots/x509.yaml": root}
		node := pfMem(fileSet)
		if flags&1 != 0 {
			node.put("want/roots/other.yaml", &pfNode{kind: "file", data: []byte(other)})
		}
		if flags&2 != 0 {
			node.put("requests/"+strings.ReplaceAll(request, "/", "_")+"/request.json", &pfNode{kind: "file", data: []byte(other)})
		}
		if flags&4 != 0 {
			node.put("history/"+name1+"/attempt.json", &pfNode{kind: "file", data: []byte(other)})
		}
		if flags&8 != 0 {
			node.put("roots/A/root.json", &pfNode{kind: "file", data: []byte(other)})
		}
		if flags&16 != 0 {
			node.put("trust/1-aaaaaaaa/root-list.json", &pfNode{kind: "file", data: []byte(other)})
		}
		if flags&32 != 0 {
			node.put("want/delegations/d.yaml", &pfNode{kind: "file", data: []byte(other)})
		}
		if flags&64 != 0 {
			node.put("requests", &pfNode{kind: "link"})
		}
		found, err := ceremony.Find(context.Background(), ceremony.FindInput{FS: pfFS{node}})
		if err != nil {
			if found != nil {
				t.Fatalf("an error with a Found: %v", err)
			}
			return
		}
		if found.Nothing() {
			if len(found.Applies) != 0 {
				t.Fatalf("nothing to apply and %d changes", len(found.Applies))
			}
			return
		}
		// What Find accepts, MakePlan makes a plan of, and the reader of the run accepts it.
		if len(found.Applies) != 2 || !found.Root.Valid() || !found.Settings.Valid() || len(found.Wanted) != 2 {
			t.Fatalf("a Found with no shape: %+v", found)
		}
		p, err := ceremony.MakePlan(found, pfEnv())
		if err != nil {
			t.Fatalf("Find accepted a bundle that MakePlan refuses: %v", err)
		}
		if _, err := ceremony.ReadPlanOut(p.JSON); err != nil {
			t.Fatalf("a plan that MakePlan made is refused by the reader: %v", err)
		}
		for _, l := range p.Words() {
			if !pfPrintable(l) {
				t.Fatalf("the words hold %+q", l)
			}
		}
	})
}

func FuzzWords(f *testing.F) {
	f.Add(pfName, "v1", "linux/amd64", "A", "A.x509.key.pem", "requests/a", "a reason", "ritueel.yaml")
	f.Add("a\nb", "\x00", "\xff", "\x1b[2J", "\xe2\x80\xae", "\\", "\r\n", "\t")
	f.Fuzz(func(t *testing.T, name, version, osArch, label, place, object, reason, path string) {
		p := &ceremony.PlanOut{
			Name:       name,
			SHA256:     pfGoldenDigest,
			Program:    buildinfo.Program{Version: version, OSArch: osArch},
			Births:     []ceremony.PlanBirth{{Label: label, Place: place}},
			LeavesOut:  []ceremony.LeftOut{{Object: object, Reason: reason}},
			Wanted:     []files.FileRef{{Path: path, SHA256: pfSumSet}},
			Signatures: make([]ceremony.PlanSignature, 3),
		}
		words := p.Words()
		if name == "" {
			if len(words) != 0 {
				t.Fatal("words of a plan with no name")
			}
			return
		}
		if len(words) == 0 || words[len(words)-1] != "plan digest "+pfGoldenDigest {
			t.Fatalf("the digest is not the last line: %q", words)
		}
		for _, l := range words {
			if !pfPrintable(l) {
				t.Fatalf("the line %+q is not printable ASCII on one line", l)
			}
		}
	})
}
