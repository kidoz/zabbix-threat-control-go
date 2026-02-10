package zabbix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"log/slog"

	"github.com/kidoz/zabbix-threat-control-go/internal/config"
)

// Sender wraps zabbix_sender for sending data to Zabbix
type Sender struct {
	cfg *config.Config
	log *slog.Logger
}

// SenderData represents data to be sent to Zabbix
type SenderData struct {
	Host  string
	Key   string
	Value string
}

// NewSender creates a new Zabbix sender
func NewSender(cfg *config.Config, log *slog.Logger) *Sender {
	return &Sender{
		cfg: cfg,
		log: log,
	}
}

// Send sends data to Zabbix using zabbix_sender
func (s *Sender) Send(data []SenderData) error {
	if len(data) == 0 {
		return nil
	}

	// Build input data
	var lines []string
	for _, d := range data {
		// Format: hostname key value
		// Escape newlines in values
		value := strings.ReplaceAll(d.Value, "\n", "\\n")
		lines = append(lines, fmt.Sprintf(`%s %s %s`, d.Host, d.Key, value))
	}

	input := strings.Join(lines, "\n")

	s.log.Debug("Sending data to Zabbix", slog.Int("items", len(data)))

	// Execute zabbix_sender with a timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, //nolint:gosec // G204: args come from validated config, not user input
		s.cfg.Zabbix.SenderPath,
		"-z", s.cfg.Zabbix.ServerFQDN,
		"-p", fmt.Sprintf("%d", s.cfg.Zabbix.ServerPort),
		"-i", "-", // read from stdin
	)

	cmd.Stdin = bytes.NewReader([]byte(input))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("zabbix_sender failed: %w: %s", err, string(output))
	}

	s.log.Debug("zabbix_sender completed", slog.String("output", string(output)))
	return nil
}

// SendLLD sends Low-Level Discovery data to Zabbix
func (s *Sender) SendLLD(host, key string, lldData *LLDData) error {
	jsonData, err := json.Marshal(lldData)
	if err != nil {
		return fmt.Errorf("failed to marshal LLD data: %w", err)
	}

	return s.Send([]SenderData{
		{
			Host:  host,
			Key:   key,
			Value: string(jsonData),
		},
	})
}

// SendJSON sends JSON data to a trapper item
func (s *Sender) SendJSON(host, key string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	return s.Send([]SenderData{
		{
			Host:  host,
			Key:   key,
			Value: string(jsonData),
		},
	})
}

// SendValue sends a single value to a trapper item
func (s *Sender) SendValue(host, key, value string) error {
	return s.Send([]SenderData{
		{
			Host:  host,
			Key:   key,
			Value: value,
		},
	})
}

// SendBatch sends multiple values efficiently
func (s *Sender) SendBatch(items []SenderData) error {
	if len(items) == 0 {
		return nil
	}

	// Process in batches to avoid command line limits
	const batchSize = 1000
	for i := 0; i < len(items); i += batchSize {
		end := i + batchSize
		if end > len(items) {
			end = len(items)
		}

		if err := s.Send(items[i:end]); err != nil {
			return err
		}
	}

	return nil
}
