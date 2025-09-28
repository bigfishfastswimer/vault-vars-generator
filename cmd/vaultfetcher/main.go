package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v3"

	"github.com/example/vaultfetcher/internal/config"
)

func main() {
	var (
		configPath    = flag.String("config", "vault_secrets.yaml", "Path to the vault secrets definition file")
		branchName    = flag.String("branch", "", "Branch name used to resolve branch-overrides")
		outputPath    = flag.String("output", filepath.Join("vault", "vault_received.yaml"), "Destination file for the received secrets")
		mountPath     = flag.String("mount", "secrets/sync", "Vault KV v2 mount path")
		passwordField = flag.String("password-field", "password", "Field within the Vault secret to read")
		vaultAddr     = flag.String("vault-addr", "", "Override Vault address (defaults to VAULT_ADDR env var)")
		timeout       = flag.Duration("timeout", 30*time.Second, "Maximum duration for a single Vault request")
	)

	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	branch := resolveBranchName(*branchName)

	addr := strings.TrimSpace(*vaultAddr)
	if addr == "" {
		addr = strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	}
	if addr == "" {
		log.Fatal("VAULT_ADDR environment variable or --vault-addr flag must be provided")
	}

	token := strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	if token == "" {
		log.Fatal("VAULT_TOKEN environment variable must be provided")
	}

	mount := strings.Trim(strings.TrimSpace(*mountPath), "/")
	if mount == "" {
		log.Fatal("mount path cannot be empty")
	}

	log.Printf("resolved branch: %q", branch)

	results := make([]string, 0, len(cfg.VaultSecrets))

	for _, secret := range cfg.VaultSecrets {
		target := secret.TargetForBranch(branch)
		password, err := fetchPassword(context.Background(), addr, token, mount, target, *passwordField, *timeout)
		if err != nil {
			log.Fatalf("fetch secret %q: %v", secret.Name, err)
		}
		results = append(results, fmt.Sprintf("%s=%s", secret.Name, password))
		log.Printf("retrieved secret %q from namespace %q", secret.Name, target.Namespace)
	}

	if err := writeOutput(*outputPath, results); err != nil {
		log.Fatalf("write output: %v", err)
	}

	log.Printf("wrote %d secrets to %s", len(results), *outputPath)
}

func resolveBranchName(flagValue string) string {
	if strings.TrimSpace(flagValue) != "" {
		return flagValue
	}

	envVars := []string{
		"BAMBOO_PLAN_REPOSITORY_BRANCH",
		"BAMBOO_REPO_BRANCH",
		"BAMBOO_BRANCH_NAME",
		"GIT_BRANCH",
		"BRANCH_NAME",
	}

	for _, env := range envVars {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
	}

	return ""
}

func fetchPassword(ctx context.Context, addr, token, mount string, target config.Target, passwordField string, timeout time.Duration) (string, error) {
	conf := api.DefaultConfig()
	conf.Address = addr

	client, err := api.NewClient(conf)
	if err != nil {
		return "", fmt.Errorf("new client: %w", err)
	}

	client.SetToken(token)
	if strings.TrimSpace(target.Namespace) != "" {
		client.SetNamespace(target.Namespace)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	path := fmt.Sprintf("cyberark/accounts/%s", target.AccountID)
	secret, err := client.KVv2(mount).Get(ctx, path)
	if err != nil {
		return "", fmt.Errorf("read secret at %s (namespace %s): %w", path, target.Namespace, err)
	}

	value, ok := secret.Data[passwordField]
	if !ok {
		return "", fmt.Errorf("field %q missing in secret %s", passwordField, path)
	}

	password, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("field %q in secret %s is not a string", passwordField, path)
	}

	if password == "" {
		return "", errors.New("password value is empty")
	}

	return password, nil
}

func writeOutput(path string, results []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	type output struct {
		Vault []string `yaml:"vault"`
	}

	out := output{Vault: results}

	data, err := yaml.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal output: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}
