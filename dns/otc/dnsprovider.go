package otc

import (
	"fmt"

	dnscommon "github.com/dns3l/dns3l-core/dns/common"
	"github.com/dns3l/dns3l-core/dns/types"
	"github.com/dns3l/dns3l-core/util"
)

type DNSProvider struct {
	C *Config `validate:"required"`
}

func (p *DNSProvider) GetInfo() *types.DNSProviderInfo {
	return &types.DNSProviderInfo{
		Name:              p.C.Name,
		Feature:           []string{"A", "TXT"},
		ZoneNesting:       true,
		DefaultAutoDNSTTL: dnscommon.ValidateSetDefaultTTL(p.C.TTL.AutoDNS, 3600),
	}
}

func (p *DNSProvider) GetPrecheckConfig() *types.PrecheckConfig {
	conf := &p.C.PreCheck
	conf.SetDefaults()
	return conf
}

func (p *DNSProvider) GetHealth() util.Health {
	healthy, err := util.CheckHealth(
		util.CheckDNSResolution(p.C.Auth.AuthURL),
		util.CheckTCPConnection(p.C.Auth.AuthURL),
		util.CheckTLSConnection(p.C.Auth.AuthURL, true),
		// Auth check
		func() (bool, error) {
			_, err := p.Auth()
			if err != nil {
				return false, fmt.Errorf("failed to authenticate with OTC: %w", err)
			}
			return true, nil
		},
	)
	return util.Health{
		Healthy:  healthy,
		Message:  err.Error(),
		Endpoint: p.C.Auth.AuthURL,
	}
}
