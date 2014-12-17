package server

import (
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/db"
	"github.com/coreos-inc/auth/key"
	"github.com/coreos-inc/auth/pkg/health"
	"github.com/coreos-inc/auth/session"
)

type ServerConfig interface {
	Server() (*Server, error)
}

type SingleServerConfig struct {
	IssuerURL      string
	TemplateDir    string
	ClientsFile    string
	ConnectorsFile string
}

func (cfg *SingleServerConfig) Server() (*Server, error) {
	iu, err := url.Parse(cfg.IssuerURL)
	if err != nil {
		return nil, err
	}

	k, err := key.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	ks := key.NewPrivateKeySet([]*key.PrivateKey{k}, time.Now().Add(24*time.Hour))
	kRepo := key.NewPrivateKeySetRepo()
	if err = kRepo.Set(ks); err != nil {
		return nil, err
	}

	cf, err := os.Open(cfg.ClientsFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read clients from file %s: %v", cfg.ClientsFile, err)
	}
	defer cf.Close()
	ciRepo, err := newClientIdentityRepoFromReader(cf)
	if err != nil {
		return nil, fmt.Errorf("unable to read client identities from file %s: %v", cfg.ClientsFile, err)
	}

	cfgRepo, err := connector.NewConnectorConfigRepoFromFile(cfg.ConnectorsFile)
	if err != nil {
		return nil, fmt.Errorf("unable to create ConnectorConfigRepo: %v", err)
	}

	sRepo := session.NewSessionRepo()
	skRepo := session.NewSessionKeyRepo()
	sm := session.NewSessionManager(sRepo, skRepo)

	tpl, err := getTemplates(cfg.TemplateDir)
	if err != nil {
		return nil, err
	}
	ltpl, err := findLoginTemplate(tpl)
	if err != nil {
		return nil, err
	}

	km := key.NewPrivateKeyManager()
	srv := Server{
		IssuerURL:           *iu,
		KeyManager:          km,
		KeySetRepo:          kRepo,
		SessionManager:      sm,
		ClientIdentityRepo:  ciRepo,
		ConnectorConfigRepo: cfgRepo,
		Templates:           tpl,
		LoginTemplate:       ltpl,
		HealthChecks:        []health.Checkable{km},
		Connectors:          []connector.Connector{},
	}

	return &srv, nil
}

type MultiServerConfig struct {
	IssuerURL   string
	TemplateDir string
	KeySecret   string
	DatabaseURL string
}

func (cfg *MultiServerConfig) Server() (*Server, error) {
	if cfg.KeySecret == "" {
		return nil, errors.New("missing key secret")
	}

	if cfg.DatabaseURL == "" {
		return nil, errors.New("missing database connection string")
	}

	iu, err := url.Parse(cfg.IssuerURL)
	if err != nil {
		return nil, err
	}

	dbc, err := db.NewConnection(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize database connection: %v", err)
	}

	kRepo, err := db.NewPrivateKeySetRepo(dbc, cfg.KeySecret)
	if err != nil {
		return nil, fmt.Errorf("unable to create PrivateKeySetRepo: %v", err)
	}

	ciRepo := db.NewClientIdentityRepo(dbc)
	sRepo := db.NewSessionRepo(dbc)
	skRepo := db.NewSessionKeyRepo(dbc)
	cfgRepo := db.NewConnectorConfigRepo(dbc)

	sm := session.NewSessionManager(sRepo, skRepo)

	tpl, err := getTemplates(cfg.TemplateDir)
	if err != nil {
		return nil, err
	}
	ltpl, err := findLoginTemplate(tpl)
	if err != nil {
		return nil, err
	}

	dbh := db.NewHealthChecker(dbc)
	km := key.NewPrivateKeyManager()
	srv := Server{
		IssuerURL:           *iu,
		KeyManager:          km,
		KeySetRepo:          kRepo,
		SessionManager:      sm,
		ClientIdentityRepo:  ciRepo,
		ConnectorConfigRepo: cfgRepo,
		Templates:           tpl,
		LoginTemplate:       ltpl,
		HealthChecks:        []health.Checkable{km, dbh},
		Connectors:          []connector.Connector{},
	}

	return &srv, nil
}

func getTemplates(dir string) (*template.Template, error) {
	files := []string{
		path.Join(dir, LoginPageTemplateName),
		path.Join(dir, connector.LoginPageTemplateName),
	}
	return template.ParseFiles(files...)
}

func findLoginTemplate(tpls *template.Template) (*template.Template, error) {
	tpl := tpls.Lookup(LoginPageTemplateName)
	if tpl == nil {
		return nil, errors.New("unable to find login template")
	}
	return tpl, nil
}
