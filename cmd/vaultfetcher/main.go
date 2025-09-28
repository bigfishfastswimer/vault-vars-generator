package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v3"

	"github.com/bigfishfastswimer/vault-vars-generator/internal/config"
	"github.com/bigfishfastswimer/vault-vars-generator/internal/validate"
)

type CLI struct {
	ConfigPath    string        `kong:"name='config',default='vault_secrets.yaml',help='Path to the vault secrets definition file.'"`
	BranchName    string        `kong:"name='branch',help='Branch name used to resolve branch-overrides.'"`
	OutputPath    string        `kong:"name='output',default='vault/vault_received.yaml',help='Destination file for the received secrets.'"`
	MountPath     string        `kong:"name='mount',default='secrets/sync',help='Vault KV v2 mount path.'"`
	PasswordField string        `kong:"name='password-field',default='password',help='Field within the Vault secret to read.'"`
	VaultAddr     string        `kong:"name='vault-addr',help='Override Vault address (defaults to VAULT_ADDR env var).'"`
	Timeout       time.Duration `kong:"name='timeout',default='30s',help='Maximum duration for a single Vault request.'"`
	Validate      bool          `kong:"help='Validate configuration without contacting Vault.'"`
}

func main() {
	cli := CLI{}
	args := normalizeArgs(os.Args[1:])
	parser := kong.Must(&cli, kong.Name("vaultfetcher"))
	ctx, err := parser.Parse(args)
	if err != nil {
		parser.FatalIfErrorf(err)
	}
	if err := cli.Run(context.Background()); err != nil {
		ctx.FatalIfErrorf(err)
	}
}

func normalizeArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}

	normalized := make([]string, len(args))
	copy(normalized, args)

	for i, arg := range normalized {
		if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") || len(arg) <= 2 {
			continue
		}

		normalized[i] = "-" + arg
	}

	return normalized
}

func (cli *CLI) Run(ctx context.Context) error {
	cfg, err := config.Load(cli.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	branch := resolveBranchName(cli.BranchName)
	log.Printf("resolved branch: %q", branch)

	if cli.Validate {
		for _, secret := range cfg.VaultSecrets {
			if _, enabled := validate.TargetForBranch(secret, branch); !enabled {
				log.Printf("secret %q skips Vault for branch %q", secret.Name, branch)
			}
		}
		log.Printf("validation successful for %d secrets", len(cfg.VaultSecrets))
		return nil
	}

	addr := strings.TrimSpace(cli.VaultAddr)
	if addr == "" {
		addr = strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	}
	if addr == "" {
		return fmt.Errorf("VAULT_ADDR environment variable or --vault-addr flag must be provided")
	}

	token := strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	if token == "" {
		return fmt.Errorf("VAULT_TOKEN environment variable must be provided")
	}

	mount := strings.Trim(strings.TrimSpace(cli.MountPath), "/")
	if mount == "" {
		return fmt.Errorf("mount path cannot be empty")
	}

	results := make([]string, 0, len(cfg.VaultSecrets))

	for _, secret := range cfg.VaultSecrets {
		target, enabled := validate.TargetForBranch(secret, branch)
		if !enabled {
			log.Printf("skipping secret %q for branch %q because Vault is disabled", secret.Name, branch)
			continue
		}
		password, err := fetchPassword(ctx, addr, token, mount, target, cli.PasswordField, cli.Timeout)
		if err != nil {
			return fmt.Errorf("fetch secret %q: %w", secret.Name, err)
		}
		results = append(results, fmt.Sprintf("%s=%s", secret.Name, password))
		log.Printf("retrieved secret %q from namespace %q", secret.Name, target.Namespace)
	}

	if err := writeOutput(cli.OutputPath, results); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	log.Printf("wrote %d secrets to %s", len(results), cli.OutputPath)
	return nil
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
