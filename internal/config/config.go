package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// File represents the root of the vault_secrets.yaml configuration file.
type File struct {
	VaultSecrets []Secret `yaml:"vault_secrets"`
}

// Secret describes a single secret lookup definition.
type Secret struct {
	Name            string           `yaml:"name"`
	Default         TargetWrapper    `yaml:"default"`
	BranchOverrides []BranchOverride `yaml:"branch-overrides"`
}

// TargetWrapper provides parity with the YAML layout where a target is nested
// under a "vault" key.
type TargetWrapper struct {
	Vault Target `yaml:"vault"`
}

// BranchOverride allows overriding the default target for a specific branch.
type BranchOverride struct {
	Name         string `yaml:"name"`
	Vault        Target `yaml:"vault"`
	VaultEnabled *bool  `yaml:"vault_enabled"`
}

// Target contains the fields required to locate the secret in Vault.
type Target struct {
	AccountID      string `yaml:"account_id"`
	Namespace      string `yaml:"namespace"`
	NamespaceAlias string `yaml:"namepsace"`
}

// Normalize normalises data read from YAML into canonical form.
func (t *Target) Normalize() {
	if t.Namespace == "" {
		t.Namespace = t.NamespaceAlias
	}
}

// Load reads and validates a configuration file from disk.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg File
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Normalize walks the configuration applying normalisation rules.
func (f *File) Normalize() {
	for i := range f.VaultSecrets {
		f.VaultSecrets[i].Normalize()
	}
}

// Normalize applies normalisation to the secret and its nested targets.
func (s *Secret) Normalize() {
	s.Default.Vault.Normalize()
	for i := range s.BranchOverrides {
		s.BranchOverrides[i].Vault.Normalize()
	}
}

// Validate ensures the configuration adheres to the expected schema and
// business rules.
func (f *File) Validate() error {
	if len(f.VaultSecrets) == 0 {
		return &ValidationError{Issues: []string{"no vault_secrets entries defined"}}
	}

	var issues []string
	seenNames := make(map[string]int)
	for i := range f.VaultSecrets {
		s := &f.VaultSecrets[i]
		if strings.TrimSpace(s.Name) == "" {
			issues = append(issues, fmt.Sprintf("secret at index %d is missing a name", i))
		} else {
			seenNames[s.Name]++
			if seenNames[s.Name] > 1 {
				issues = append(issues, fmt.Sprintf("duplicate secret name %q", s.Name))
			}
		}

		hasDefault := targetDefined(s.Default.Vault)
		if hasDefault {
			if err := validateTarget(s.Default.Vault, fmt.Sprintf("secret %q default", s.Name)); err != nil {
				issues = append(issues, err.Error())
			}
		}

		if !hasDefault && len(s.BranchOverrides) == 0 {
			issues = append(issues, fmt.Sprintf("secret %q must define a default target or at least one branch override", s.Name))
		}

		overrideNames := make(map[string]struct{})
		for j := range s.BranchOverrides {
			o := &s.BranchOverrides[j]
			if strings.TrimSpace(o.Name) == "" {
				issues = append(issues, fmt.Sprintf("secret %q override at index %d missing name", s.Name, j))
			} else {
				if _, ok := overrideNames[o.Name]; ok {
					issues = append(issues, fmt.Sprintf("secret %q has duplicate override for branch %q", s.Name, o.Name))
				}
				overrideNames[o.Name] = struct{}{}
			}
			enabled := true
			if o.VaultEnabled != nil {
				enabled = *o.VaultEnabled
			}

			if !enabled {
				if targetDefined(o.Vault) {
					issues = append(issues, fmt.Sprintf("secret %q override %q disables vault but defines a vault target", s.Name, o.Name))
				}
				continue
			}

			if !targetDefined(o.Vault) {
				issues = append(issues, fmt.Sprintf("secret %q override %q must define a vault target when vault is enabled", s.Name, o.Name))
				continue
			}

			if err := validateTarget(o.Vault, fmt.Sprintf("secret %q override %q", s.Name, o.Name)); err != nil {
				issues = append(issues, err.Error())
			}

			if hasDefault && targetsEqual(o.Vault, s.Default.Vault) {
				issues = append(issues, fmt.Sprintf("secret %q override %q must not match the default vault target", s.Name, o.Name))
			}
		}
	}

	if len(issues) > 0 {
		return &ValidationError{Issues: issues}
	}

	return nil
}

func targetDefined(t Target) bool {
	return strings.TrimSpace(t.AccountID) != "" || strings.TrimSpace(t.Namespace) != ""
}

func targetsEqual(a, b Target) bool {
	return strings.TrimSpace(a.AccountID) == strings.TrimSpace(b.AccountID) && strings.TrimSpace(a.Namespace) == strings.TrimSpace(b.Namespace)
}

func validateTarget(t Target, context string) error {
	if strings.TrimSpace(t.AccountID) == "" && strings.TrimSpace(t.Namespace) == "" {
		return fmt.Errorf("%s: missing account_id and namespace", context)
	}

	var issues []string
	if strings.TrimSpace(t.AccountID) == "" {
		issues = append(issues, "account_id is required")
	}
	if strings.TrimSpace(t.Namespace) == "" {
		issues = append(issues, "namespace is required")
	}

	if len(issues) > 0 {
		return fmt.Errorf("%s: %s", context, strings.Join(issues, ", "))
	}

	return nil
}

// ValidationError groups schema validation issues.
type ValidationError struct {
	Issues []string
}

// Error implements the error interface.
func (v *ValidationError) Error() string {
	return fmt.Sprintf("configuration validation failed: %s", strings.Join(v.Issues, "; "))
}

// Is allows errors.Is checks against ValidationError.
func (v *ValidationError) Is(target error) bool {
	_, ok := target.(*ValidationError)
	return ok
}

// MustDefaultBranchTarget fetches the default target, ensuring it is valid.
func (s *Secret) MustDefaultBranchTarget() (Target, error) {
	if !targetDefined(s.Default.Vault) {
		return Target{}, errors.New("default vault target is not defined")
	}
	if err := validateTarget(s.Default.Vault, "secret default"); err != nil {
		return Target{}, err
	}
	return s.Default.Vault, nil
}
