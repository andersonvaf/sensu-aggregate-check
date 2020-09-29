package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/sensu-community/sensu-plugin-sdk/sensu"
	corev2 "github.com/sensu/sensu-go/api/core/v2"
	"github.com/sensu/sensu-go/types"
)

// Config represents the check plugin config.
type Config struct {
	sensu.PluginConfig
	CheckLabels        string
	EntityLabels       string
	Namespaces         string
	APIHost            string
	APIPort            int
	APIUrl             string
	APIUser            string
	APIPass            string
	APIKey             string
	UseAPIUrl          bool
	Secure             bool
	TrustedCAFile      string
	InsecureSkipVerify bool
	Protocol           string
	WarnPercent        int
	CritPercent        int
	WarnCount          int
	CritCount          int
	OutputLimit        int
}

// Auth represents the authentication info
type Auth struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// Counters represents the analyzed components and statuses count
type Counters struct {
	Entities int
	Checks   int
	Ok       int
	Warning  int
	Critical int
	Unknown  int
	Total    int
}

var (
	tlsConfig tls.Config

	plugin = Config{
		PluginConfig: sensu.PluginConfig{
			Name:     "sensu-aggregate-check",
			Short:    "The Sensu Go Event Aggregates Check plugin modified by Reliant",
			Keyspace: "reliant.io/plugins/sensu-aggregate-check/config",
		},
	}

	options = []*sensu.PluginConfigOption{
		&sensu.PluginConfigOption{
			Path:      "check-labels",
			Env:       "",
			Argument:  "check-labels",
			Shorthand: "l",
			Default:   "",
			Usage:     "Comma-delimited list of Sensu Go Event Check Names to be aggregated (e.g. 'check1,check2,check3')",
			Value:     &plugin.CheckLabels,
		},
		&sensu.PluginConfigOption{
			Path:      "entity-labels",
			Env:       "",
			Argument:  "entity-labels",
			Shorthand: "e",
			Default:   "",
			Usage:     "Comma-delimited list of Sensu Go Event Entity Names to be aggregated (e.g. 'entity1,entity2')",
			Value:     &plugin.EntityLabels,
		},
		&sensu.PluginConfigOption{
			Path:      "namespaces",
			Env:       "",
			Argument:  "namespaces",
			Shorthand: "n",
			Default:   "default",
			Usage:     "Comma-delimited list of Sensu Go Namespaces to query for Events (e.g. 'us-east-1,us-west-2')",
			Value:     &plugin.Namespaces,
		},
		&sensu.PluginConfigOption{
			Path:      "api-host",
			Env:       "",
			Argument:  "api-host",
			Shorthand: "H",
			Default:   "127.0.0.1",
			Usage:     "Sensu Go Backend API Host (e.g. 'sensu-backend.example.com')",
			Value:     &plugin.APIHost,
		},
		&sensu.PluginConfigOption{
			Path:      "api-port",
			Env:       "",
			Argument:  "api-port",
			Shorthand: "p",
			Default:   4567,
			Usage:     "Sensu Go Backend API Port (e.g. 8080)",
			Value:     &plugin.APIPort,
		},
		&sensu.PluginConfigOption{
			Path:      "api-url",
			Env:       "",
			Argument:  "api-url",
			Shorthand: "U",
			Default:   "http://sensu:4567",
			Usage:     "Sensu Go Backend API URL (e.g. http://sensu:4567)",
			Value:     &plugin.APIUrl,
		},
		&sensu.PluginConfigOption{
			Path:      "api-user",
			Env:       "SENSU_API_USER",
			Argument:  "api-user",
			Shorthand: "u",
			Default:   "admin",
			Usage:     "Sensu Go Backend API User",
			Value:     &plugin.APIUser,
		},
		&sensu.PluginConfigOption{
			Path:      "api-pass",
			Env:       "SENSU_API_PASSWORD",
			Argument:  "api-pass",
			Shorthand: "P",
			Default:   "P@ssw0rd!",
			Usage:     "Sensu Go Backend API Password",
			Value:     &plugin.APIPass,
		},
		&sensu.PluginConfigOption{
			Path:      "api-key",
			Env:       "SENSU_API_KEY",
			Argument:  "api-key",
			Shorthand: "k",
			Default:   "",
			Usage:     "Sensu Go Backend API Key",
			Value:     &plugin.APIKey,
		},
		&sensu.PluginConfigOption{
			Path:      "warn-percent",
			Env:       "",
			Argument:  "warn-percent",
			Shorthand: "w",
			Default:   0,
			Usage:     "Warning threshold - % of Events in warning state",
			Value:     &plugin.WarnPercent,
		},
		&sensu.PluginConfigOption{
			Path:      "crit-percent",
			Env:       "",
			Argument:  "crit-percent",
			Shorthand: "c",
			Default:   0,
			Usage:     "Critical threshold - % of Events in warning state",
			Value:     &plugin.CritPercent,
		},
		&sensu.PluginConfigOption{
			Path:      "warn-count",
			Env:       "",
			Argument:  "warn-count",
			Shorthand: "W",
			Default:   0,
			Usage:     "Warning threshold - count of Events in warning state",
			Value:     &plugin.WarnCount,
		},
		&sensu.PluginConfigOption{
			Path:      "crit-count",
			Env:       "",
			Argument:  "crit-count",
			Shorthand: "C",
			Default:   0,
			Usage:     "Critical threshold - count of Events in warning state",
			Value:     &plugin.CritCount,
		},
		&sensu.PluginConfigOption{
			Path:      "secure",
			Env:       "",
			Argument:  "secure",
			Shorthand: "s",
			Default:   false,
			Usage:     "Use TLS connection to API",
			Value:     &plugin.Secure,
		},
		&sensu.PluginConfigOption{
			Path:      "insecure-skip-verify",
			Env:       "",
			Argument:  "insecure-skip-verify",
			Shorthand: "i",
			Default:   false,
			Usage:     "skip TLS certificate verification (not recommended!)",
			Value:     &plugin.InsecureSkipVerify,
		},
		&sensu.PluginConfigOption{
			Path:      "trusted-ca-file",
			Env:       "",
			Argument:  "trusted-ca-file",
			Shorthand: "t",
			Default:   "",
			Usage:     "TLS CA certificate bundle in PEM format",
			Value:     &plugin.TrustedCAFile,
		},
		&sensu.PluginConfigOption{
			Path:      "output-limit",
			Env:       "",
			Argument:  "output-limit",
			Shorthand: "o",
			Default:   10,
			Usage:     "If the number of checks is greater than the output limit, only the counters will be printed in the output",
			Value:     &plugin.OutputLimit,
		},
	}
)

func main() {
	check := sensu.NewGoCheck(&plugin.PluginConfig, options, checkArgs, executeCheck, false)
	check.Execute()
}

func checkArgs(event *types.Event) (int, error) {
	if len(plugin.CheckLabels) == 0 {
		return sensu.CheckStateWarning, fmt.Errorf("--check-labels is required")
	}

	if len(plugin.APIUrl) != 0 {
		if strings.Contains(plugin.APIUrl, "https") {
			plugin.Secure = true
		} else {
			plugin.Secure = false
		}
	} else {
		if plugin.Secure {
			plugin.Protocol = "https"
		} else {
			plugin.Protocol = "http"
		}

		plugin.APIUrl = fmt.Sprintf("%s://%s:%d", plugin.Protocol, plugin.APIHost, plugin.APIPort)
	}

	if len(plugin.TrustedCAFile) > 0 {
		caCertPool, err := corev2.LoadCACerts(plugin.TrustedCAFile)
		if err != nil {
			return sensu.CheckStateWarning, fmt.Errorf("Error loading specified CA file")
		}
		tlsConfig.RootCAs = caCertPool
	}
	tlsConfig.InsecureSkipVerify = plugin.InsecureSkipVerify

	tlsConfig.BuildNameToCertificate()
	tlsConfig.CipherSuites = corev2.DefaultCipherSuites

	return sensu.CheckStateOK, nil
}

func authenticate() (Auth, error) {
	var auth Auth
	client := http.DefaultClient
	client.Transport = http.DefaultTransport

	if plugin.Secure {
		client.Transport.(*http.Transport).TLSClientConfig = &tlsConfig
	}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/auth", plugin.APIUrl),
		nil,
	)
	if err != nil {
		return auth, fmt.Errorf("error generating auth request: %v", err)
	}

	req.SetBasicAuth(plugin.APIUser, plugin.APIPass)

	resp, err := client.Do(req)
	if err != nil {
		return auth, fmt.Errorf("error executing auth request: %v", err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return auth, fmt.Errorf("error reading auth response: %v", err)
	}

	if strings.HasPrefix(string(body), "Unauthorized") {
		return auth, fmt.Errorf("authorization failed for user %s", plugin.APIUser)
	}

	err = json.NewDecoder(bytes.NewReader(body)).Decode(&auth)

	if err != nil {
		return auth, fmt.Errorf("error decoding auth response: %v\nResponse: %s", err, body)
	}

	return auth, err
}

func getEvent(auth Auth, namespace string, entity string, check string) (types.Event, error) {
	client := http.DefaultClient
	client.Transport = http.DefaultTransport

	url := fmt.Sprintf("%s/api/core/v2/namespaces/%s/events/%s/%s", plugin.APIUrl, namespace, entity, check)
	event := types.Event{}

	if plugin.Secure {
		client.Transport.(*http.Transport).TLSClientConfig = &tlsConfig
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return event, fmt.Errorf("error creating GET request for %s: %v", url, err)
	}

	if len(plugin.APIKey) == 0 {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.AccessToken))
	} else {
		req.Header.Set("Authorization", fmt.Sprintf("Key %s", plugin.APIKey))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return event, fmt.Errorf("error executing GET request for %s: %v", url, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return event, fmt.Errorf("error reading response body during getEvents: %v", err)
	}

	err = json.Unmarshal(body, &event)
	if err != nil {
		return event, fmt.Errorf("error unmarshalling response during getEvents: %v\nResponse: %s", err, body)
	}

	return event, err
}

func getAllEvents(auth Auth, namespace string) ([]types.Event, error) {
	client := http.DefaultClient
	client.Transport = http.DefaultTransport

	url := fmt.Sprintf("%s/api/core/v2/namespaces/%s/events", plugin.APIUrl, namespace)
	events := []types.Event{}

	if plugin.Secure {
		client.Transport.(*http.Transport).TLSClientConfig = &tlsConfig
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return events, fmt.Errorf("error creating GET request for %s: %v", url, err)
	}

	if len(plugin.APIKey) == 0 {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.AccessToken))
	} else {
		req.Header.Set("Authorization", fmt.Sprintf("Key %s", plugin.APIKey))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return events, fmt.Errorf("error executing GET request for %s: %v", url, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return events, fmt.Errorf("error reading response body during getEvents: %v", err)
	}

	err = json.Unmarshal(body, &events)
	if err != nil {
		return events, fmt.Errorf("error unmarshalling response during getEvents: %v\nResponse: %s", err, body)
	}
	result := filterEvents(events)

	return result, err
}

func filterEvents(events []types.Event) []types.Event {
	result := []types.Event{}

	cLabels := strings.Split(plugin.CheckLabels, ",")
	eLabels := strings.Split(plugin.EntityLabels, ",")

	for _, event := range events {
		selected := false

		for _, label := range cLabels {
			if event.Check.ObjectMeta.Name == label {
				selected = true
				break
			}
		}

		if selected {
			for _, label := range eLabels {
				if event.Entity.ObjectMeta.Name == label {
					selected = true
					break
				}
			}
		}

		if selected {
			result = append(result, event)
		}
	}

	return result
}

func executeCheck(event *types.Event) (int, error) {
	var autherr error
	var namespaces []string
	var entity_labels []string
	var check_labels []string

	auth := Auth{}

	if len(plugin.APIKey) == 0 {
		auth, autherr = authenticate()

		if autherr != nil {
			return sensu.CheckStateUnknown, autherr
		}
	}

	namespaces = strings.Split(plugin.Namespaces, ",")
	check_labels = strings.Split(plugin.CheckLabels, ",")

	events := []types.Event{}

	counters := Counters{}

	if len(plugin.EntityLabels) == 0 {

		for _, namespace := range strings.Split(plugin.Namespaces, ",") {
			selected, err := getAllEvents(auth, namespace)

			if err != nil {
				return sensu.CheckStateUnknown, err
			}

			for _, event := range selected {
				events = append(events, event)
			}
		}

	} else {

		entity_labels = strings.Split(plugin.EntityLabels, ",")

		for _, namespace := range namespaces {
			for _, entity_label := range entity_labels {
				for _, check_label := range check_labels {
					event, err := getEvent(auth, namespace, entity_label, check_label)

					if err != nil {
						return sensu.CheckStateUnknown, err
					}

					if event.Entity == nil {
						counters.Unknown++
						counters.Total++
						fmt.Printf("[ UNKNOWN ] Is %s subscribed to %s ?\n", entity_label, check_label)
					} else {
						events = append(events, event)
					}
				}
			}
		}
	}

	entities := map[string]string{}
	checks := map[string]string{}

	eventsTotal := len(events)

	for _, event := range events {
		entities[event.Entity.ObjectMeta.Name] = ""
		checks[event.Check.ObjectMeta.Name] = ""
		status := ""

		switch event.Check.Status {
		case 0:
			counters.Ok++
			status = "OK"
		case 1:
			counters.Warning++
			status = "WARNING"
		case 2:
			counters.Critical++
			status = "CRITICAL"
		default:
			counters.Unknown++
			status = "UNKNOWN"
		}

		if eventsTotal <= plugin.OutputLimit {
			fmt.Printf("[ %s ] %s in %s\n", status, event.Check.ObjectMeta.Name, event.Entity.ObjectMeta.Name)
		}

		counters.Total++
	}

	counters.Entities = len(entities)
	counters.Checks = len(checks)

	fmt.Printf("\nCounters: %+v\n", counters)

	if counters.Total == 0 {
		fmt.Printf("WARNING: No Events returned for Aggregate\n")
		return sensu.CheckStateWarning, nil
	}

	percent := int((float64(counters.Ok) / float64(counters.Total)) * 100)

	fmt.Printf("Percent OK: %v\n\n", percent)

	if plugin.CritPercent != 0 {
		if percent < plugin.CritPercent {
			fmt.Printf("CRITICAL: Less than %d%% percent OK (%d%%)\n", plugin.CritPercent, percent)
			return sensu.CheckStateCritical, nil
		}
	}

	if plugin.WarnPercent != 0 {
		if percent < plugin.WarnPercent {
			fmt.Printf("WARNING: Less than %d%% percent OK (%d%%)\n", plugin.WarnPercent, percent)
			return sensu.CheckStateWarning, nil
		}
	}

	if plugin.CritCount != 0 {
		if counters.Critical >= plugin.CritCount {
			fmt.Printf("CRITICAL: %d or more Events are in a Critical state (%d)\n", plugin.CritCount, counters.Critical)
			return sensu.CheckStateCritical, nil
		}
	}

	if plugin.WarnCount != 0 {
		if counters.Warning >= plugin.WarnCount {
			fmt.Printf("WARNING: %d or more Events are in a Warning state (%d)\n", plugin.WarnCount, counters.Warning)
			return sensu.CheckStateWarning, nil
		}
	}

	fmt.Printf("Everything is OK\n")

	return sensu.CheckStateOK, nil
}
