package setup

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func validOperator() OperatorInput {
	return OperatorInput{ID: "Fabio", Passphrase: "correct horse battery", Confirm: "correct horse battery"}
}

func validHub() HubInput {
	return HubInput{Name: "frpi5", TimeZone: "UTC", AgentHost: "frpi5.local", HTTPSPort: 8443, RetentionDays: 90}
}

func TestSubmitOperator(t *testing.T) {
	strong := func(p string) error {
		if strings.Contains(p, "password") {
			return errors.New("Too common.")
		}
		return nil
	}
	tests := []struct {
		name    string
		in      OperatorInput
		badKeys []string
	}{
		{"ok", validOperator(), nil},
		{"short id", OperatorInput{"ab", "correct horse battery", "correct horse battery"}, []string{"id"}},
		{"long id", OperatorInput{strings.Repeat("a", 33), "correct horse battery", "correct horse battery"}, []string{"id"}},
		{"bad chars", OperatorInput{"fa bio", "correct horse battery", "correct horse battery"}, []string{"id"}},
		{"short pass", OperatorInput{"fabio", "short", "short"}, []string{"passphrase"}},
		{"mismatch", OperatorInput{"fabio", "correct horse battery", "correct horse batterY"}, []string{"confirm"}},
		{"injected check", OperatorInput{"fabio", "my password is long", "my password is long"}, []string{"passphrase"}},
		{"all bad", OperatorInput{"!", "x", "y"}, []string{"id", "passphrase", "confirm"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := wizardAt(StepOperator, WizardOptions{CheckPassphrase: strong})
			err := w.SubmitOperator(tc.in)
			if len(tc.badKeys) == 0 {
				if err != nil {
					t.Fatal(err)
				}
				r := w.res
				if r.OperatorID != "fabio" {
					t.Fatalf("id not lower-cased: %q", r.OperatorID)
				}
				return
			}
			var ve ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("err = %v", err)
			}
			for _, k := range tc.badKeys {
				if _, ok := ve[k]; !ok {
					t.Errorf("missing error for %s: %v", k, ve)
				}
			}
			if len(ve) != len(tc.badKeys) {
				t.Errorf("errors = %v", ve)
			}
		})
	}
}

func TestSubmitHub(t *testing.T) {
	mod := func(f func(*HubInput)) HubInput { h := validHub(); f(&h); return h }
	tests := []struct {
		name string
		in   HubInput
		bad  string
	}{
		{"ok", validHub(), ""},
		{"ip host", mod(func(h *HubInput) { h.AgentHost = "192.168.1.10" }), ""},
		{"empty name", mod(func(h *HubInput) { h.Name = " " }), "name"},
		{"bad zone", mod(func(h *HubInput) { h.TimeZone = "Mars/Base" }), "timezone"},
		{"empty zone", mod(func(h *HubInput) { h.TimeZone = "" }), "timezone"},
		{"empty host", mod(func(h *HubInput) { h.AgentHost = "" }), "agent_host"},
		{"host with space", mod(func(h *HubInput) { h.AgentHost = "a b" }), "agent_host"},
		{"host with port", mod(func(h *HubInput) { h.AgentHost = "frpi5:8443" }), "agent_host"},
		{"port 0", mod(func(h *HubInput) { h.HTTPSPort = 0 }), "https_port"},
		{"port high", mod(func(h *HubInput) { h.HTTPSPort = 65536 }), "https_port"},
		{"port max", mod(func(h *HubInput) { h.HTTPSPort = 65535 }), ""},
		{"retention", mod(func(h *HubInput) { h.RetentionDays = 7 }), "retention"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := wizardAt(StepHub, WizardOptions{}).SubmitHub(tc.in)
			if tc.bad == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var ve ValidationError
			if !errors.As(err, &ve) || len(ve) != 1 || ve[tc.bad] == "" {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestSubmitSelfLink(t *testing.T) {
	w := wizardAt(StepSelfLink, WizardOptions{})
	var ve ValidationError
	if err := w.SubmitSelfLink(SelfLinkInput{Enabled: true, Capabilities: []string{"shell", "bogus"}}); !errors.As(err, &ve) {
		t.Fatalf("err = %v", err)
	}
	if err := w.SubmitSelfLink(SelfLinkInput{Enabled: true, Capabilities: []string{"shell", "monitoring", "shell"}}); err != nil {
		t.Fatal(err)
	}
	if got := w.res.SelfLink.Capabilities; !reflect.DeepEqual(got, []string{"monitoring", "shell"}) {
		t.Fatalf("caps = %v", got)
	}
	w2 := wizardAt(StepSelfLink, WizardOptions{})
	if err := w2.SubmitSelfLink(SelfLinkInput{Enabled: false, Capabilities: []string{"shell"}}); err != nil {
		t.Fatal(err)
	}
	if w2.res.SelfLink.Capabilities != nil {
		t.Fatal("caps kept while disabled")
	}
}

func TestTwoFactor(t *testing.T) {
	w := NewWizard(WizardOptions{})
	if err := w.SubmitOperator(validOperator()); err == nil {
		t.Fatal("operator must be blocked before trust")
	}
	w.SubmitTrust()
	w.SubmitOperator(validOperator())
	var ve ValidationError
	if err := w.SubmitTwoFactor(false, " "); !errors.As(err, &ve) {
		t.Fatalf("err = %v", err)
	}
	if err := w.SubmitTwoFactor(false, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	if w.res.TOTPSecret != "JBSWY3DPEHPK3PXP" || w.res.TOTPSkipped {
		t.Fatalf("res = %+v", w.res)
	}
	if err := w.SubmitTwoFactor(true, "ignored"); err != nil {
		t.Fatal(err)
	}
	if w.res.TOTPSecret != "" || !w.res.TOTPSkipped {
		t.Fatalf("skip kept secret: %+v", w.res)
	}
}

func TestNavigation(t *testing.T) {
	w := NewWizard(WizardOptions{})
	if w.Current() != StepTrust || !w.Done(StepUnlock) {
		t.Fatal("initial state")
	}
	if err := w.Goto(StepOperator); !errors.Is(err, ErrStepLocked) {
		t.Fatalf("jump ahead: %v", err)
	}
	if err := w.SubmitHub(validHub()); !errors.Is(err, ErrStepLocked) {
		t.Fatalf("submit ahead: %v", err)
	}
	if _, err := w.Result(); !errors.Is(err, ErrNotReady) {
		t.Fatalf("result early: %v", err)
	}
	must(t, w.SubmitTrust())
	if w.Current() != StepOperator {
		t.Fatalf("current = %v", w.Current())
	}
	must(t, w.SubmitOperator(validOperator()))
	must(t, w.SubmitTwoFactor(true, ""))
	must(t, w.SubmitHub(validHub()))
	if w.Current() != StepSelfLink {
		t.Fatalf("current = %v", w.Current())
	}
	if err := w.Goto(StepReady); !errors.Is(err, ErrStepLocked) {
		t.Fatalf("ready early: %v", err)
	}
	// Back and re-edit.
	if w.Back() != StepHub || w.Back() != StepTwoFactor {
		t.Fatal("back")
	}
	must(t, w.Goto(StepSelfLink))
	must(t, w.SubmitSelfLink(SelfLinkInput{Enabled: true, Capabilities: []string{"monitoring"}}))
	if w.Current() != StepReady {
		t.Fatalf("current = %v", w.Current())
	}
	res, err := w.Result()
	if err != nil {
		t.Fatal(err)
	}
	if res.OperatorID != "fabio" || res.Hub.Name != "frpi5" || !res.TOTPSkipped || !res.SelfLink.Enabled {
		t.Fatalf("result = %+v", res)
	}
	for w.Back() > StepTrust {
	}
	if w.Back() != StepTrust {
		t.Fatal("back below trust")
	}
	if StepTwoFactor.String() != "two-factor" {
		t.Fatal("step name")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// wizardAt returns a wizard whose earlier steps are complete.
func wizardAt(target Step, o WizardOptions) *Wizard {
	w := NewWizard(o)
	for s := StepTrust; s < target; s++ {
		w.done[s] = true
	}
	w.cur = target
	return w
}
