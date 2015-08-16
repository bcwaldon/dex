package server

import (
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	texttemplate "text/template"
	"time"

	"github.com/coreos-inc/auth/client"
	"github.com/coreos-inc/auth/connector"
	"github.com/coreos-inc/auth/db"
	"github.com/coreos-inc/auth/email"
	"github.com/coreos-inc/auth/repo"
	"github.com/coreos-inc/auth/session"
	"github.com/coreos-inc/auth/user"
	"github.com/coreos/go-oidc/key"
	"github.com/coreos/pkg/health"
)

type ServerConfig interface {
	Server() (*Server, error)
}

type SingleServerConfig struct {
	IssuerURL         string
	TemplateDir       string
	EmailTemplateDirs []string
	ClientsFile       string
	ConnectorsFile    string
	EmailerConfigFile string
	UsersFile         string
	EmailFromAddress  string
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
	ciRepo, err := client.NewClientIdentityRepoFromReader(cf)
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

	userRepo, err := user.NewUserRepoFromFile(cfg.UsersFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read users from file: %v", err)
	}

	passwordInfoRepo := user.NewPasswordInfoRepo()
	txnFactory := repo.InMemTransactionFactory
	userManager := user.NewManager(userRepo, passwordInfoRepo, txnFactory, user.ManagerOptions{})

	km := key.NewPrivateKeyManager()
	srv := Server{
		IssuerURL:           *iu,
		KeyManager:          km,
		KeySetRepo:          kRepo,
		SessionManager:      sm,
		ClientIdentityRepo:  ciRepo,
		ConnectorConfigRepo: cfgRepo,
		Templates:           tpl,

		HealthChecks:     []health.Checkable{km},
		Connectors:       []connector.Connector{},
		UserRepo:         userRepo,
		PasswordInfoRepo: passwordInfoRepo,
		UserManager:      userManager,
		EmailFromAddress: cfg.EmailFromAddress,
	}

	err = setTemplates(&srv, tpl)
	if err != nil {
		return nil, err
	}

	err = setEmailer(&srv, cfg.EmailerConfigFile, cfg.EmailTemplateDirs)
	if err != nil {
		return nil, err
	}

	return &srv, nil
}

type MultiServerConfig struct {
	IssuerURL         string
	TemplateDir       string
	KeySecret         string
	DatabaseConfig    db.Config
	EmailTemplateDirs []string
	EmailerConfigFile string
	EmailFromAddress  string
}

func (cfg *MultiServerConfig) Server() (*Server, error) {
	if cfg.KeySecret == "" {
		return nil, errors.New("missing key secret")
	}

	if cfg.DatabaseConfig.DSN == "" {
		return nil, errors.New("missing database connection string")
	}

	iu, err := url.Parse(cfg.IssuerURL)
	if err != nil {
		return nil, err
	}

	dbc, err := db.NewConnection(cfg.DatabaseConfig)
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
	userRepo := db.NewUserRepo(dbc)
	pwiRepo := db.NewPasswordInfoRepo(dbc)
	userManager := user.NewManager(userRepo, pwiRepo, db.TransactionFactory(dbc), user.ManagerOptions{})
	refreshTokenRepo := db.NewRefreshTokenRepo(dbc)

	sm := session.NewSessionManager(sRepo, skRepo)

	tpl, err := getTemplates(cfg.TemplateDir)
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
		HealthChecks:        []health.Checkable{km, dbh},
		Connectors:          []connector.Connector{},
		UserRepo:            userRepo,
		UserManager:         userManager,
		PasswordInfoRepo:    pwiRepo,
		RefreshTokenRepo:    refreshTokenRepo,
		EmailFromAddress:    cfg.EmailFromAddress,
	}
	err = setTemplates(&srv, tpl)
	if err != nil {
		return nil, err
	}

	err = setEmailer(&srv, cfg.EmailerConfigFile, cfg.EmailTemplateDirs)
	if err != nil {
		return nil, err
	}

	return &srv, nil
}

func getTemplates(dir string) (*template.Template, error) {
	return template.ParseGlob(dir + "/*.html")
}

func setTemplates(srv *Server, tpls *template.Template) error {
	ltpl, err := findTemplate(LoginPageTemplateName, tpls)
	if err != nil {
		return err
	}
	srv.LoginTemplate = ltpl

	rtpl, err := findTemplate(RegisterTemplateName, tpls)
	if err != nil {
		return err
	}
	srv.RegisterTemplate = rtpl

	vtpl, err := findTemplate(VerifyEmailTemplateName, tpls)
	if err != nil {
		return err
	}
	srv.VerifyEmailTemplate = vtpl

	srtpl, err := findTemplate(SendResetPasswordEmailTemplateName, tpls)
	if err != nil {
		return err
	}
	srv.SendResetPasswordEmailTemplate = srtpl

	rpwtpl, err := findTemplate(ResetPasswordTemplateName, tpls)
	if err != nil {
		return err
	}
	srv.ResetPasswordTemplate = rpwtpl

	return nil
}

func setEmailer(srv *Server, emailerConfigFile string, emailTemplateDirs []string) error {

	cfg, err := email.NewEmailerConfigFromFile(emailerConfigFile)
	if err != nil {
		return err
	}

	emailer, err := cfg.Emailer()
	if err != nil {
		return err
	}

	getFileNames := func(dir, ext string) ([]string, error) {
		fns, err := filepath.Glob(dir + "/*." + ext)
		if err != nil {
			return nil, err
		}
		return fns, nil
	}
	getTextFiles := func(dir string) ([]string, error) {
		return getFileNames(dir, "txt")
	}
	getHTMLFiles := func(dir string) ([]string, error) {
		return getFileNames(dir, "html")
	}

	textTemplates := texttemplate.New("textTemplates")
	htmlTemplates := template.New("htmlTemplates")
	for _, dir := range emailTemplateDirs {
		textFileNames, err := getTextFiles(dir)
		if err != nil {
			return err
		}
		if len(textFileNames) != 0 {
			textTemplates, err = textTemplates.ParseFiles(textFileNames...)
		}
		if err != nil {
			return err
		}

		htmlFileNames, err := getHTMLFiles(dir)
		if err != nil {
			return err
		}
		if len(htmlFileNames) != 0 {
			htmlTemplates, err = htmlTemplates.ParseFiles(htmlFileNames...)
		}
		if err != nil {
			return err
		}
	}
	tMailer := email.NewTemplatizedEmailerFromTemplates(textTemplates, htmlTemplates, emailer)

	srv.Emailer = tMailer
	return nil
}

func findTemplate(name string, tpls *template.Template) (*template.Template, error) {
	tpl := tpls.Lookup(name)
	if tpl == nil {
		return nil, fmt.Errorf("unable to find template: %q", name)
	}
	return tpl, nil
}
