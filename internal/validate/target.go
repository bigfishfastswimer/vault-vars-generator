package validate

import (
	"strings"

	"github.com/bigfishfastswimer/vault-vars-generator/internal/config"
)

// TargetForBranch resolves the Vault target for the given branch name. It
// returns the target and a boolean indicating whether Vault should be used for
// the resolved branch.
func TargetForBranch(secret config.Secret, branch string) (config.Target, bool) {
	candidates := branchCandidates(branch)
	for _, candidate := range candidates {
		for _, override := range secret.BranchOverrides {
			if override.Name != candidate {
				continue
			}

			enabled := true
			if override.VaultEnabled != nil {
				enabled = *override.VaultEnabled
			}
			if !enabled {
				return config.Target{}, false
			}

			if override.Vault.AccountID == "" && override.Vault.Namespace == "" {
				return config.Target{}, false
			}

			return override.Vault, true
		}
	}

	if secret.Default.Vault.AccountID == "" && secret.Default.Vault.Namespace == "" {
		return config.Target{}, false
	}
	return secret.Default.Vault, true
}

func branchCandidates(branch string) []string {
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return nil
	}

	candidates := []string{branch}

	if strings.HasPrefix(branch, "refs/heads/") {
		candidates = append(candidates, strings.TrimPrefix(branch, "refs/heads/"))
	}
	if strings.HasPrefix(branch, "origin/") {
		candidates = append(candidates, strings.TrimPrefix(branch, "origin/"))
	}

	return candidates
}
