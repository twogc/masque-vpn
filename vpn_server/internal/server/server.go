package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	common "github.com/iselt/masque-vpn/common"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Server представляет MASQUE VPN сервер
type Server struct {
	Config      common.ServerConfig
	TunDev      *common.TUNDevice
	IPPool      *common.IPPool
	ClientIPMap map[string]netip.Addr
	IPConnMap   map[netip.Addr]*ClientSession
	IPPoolMu    sync.RWMutex
	Metrics     *Metrics
	APIServer   *APIServer
}

// New создает новый экземпляр сервера
func New(config common.ServerConfig) (*Server, error) {
	networkInfo, err := common.NewNetworkInfo(config.AssignCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to create network info: %w", err)
	}

	ipPool := common.NewIPPool(networkInfo.GetPrefix(), networkInfo.GetGateway().Addr())

	var tunDev *common.TUNDevice
	if config.TunName != "" {
		tunDev, err = common.CreateTunDevice(config.TunName, net.IPNet{
			IP:   networkInfo.GetGateway().Addr().AsSlice(),
			Mask: net.CIDRMask(networkInfo.GetGateway().Bits(), networkInfo.GetGateway().Addr().BitLen()),
		}, config.MTU)
		if err != nil {
			return nil, fmt.Errorf("failed to create TUN device: %w", err)
		}
		log.Printf("TUN device created: %s", tunDev.Name())
	} else {
		log.Printf("TUN device disabled (empty tun_name)")
	}

	metrics := NewMetrics()
	if tunDev != nil {
		metrics.TunInterfaceStatus.Set(1)
	}

	server := &Server{
		Config:      config,
		TunDev:      tunDev,
		IPPool:      ipPool,
		ClientIPMap: make(map[string]netip.Addr),
		IPConnMap:   make(map[netip.Addr]*ClientSession),
		Metrics:     metrics,
	}

	apiServer, err := NewAPIServer(server)
	if err != nil {
		if tunDev != nil {
			tunDev.Close()
		}
		return nil, fmt.Errorf("failed to create API server: %w", err)
	}
	server.APIServer = apiServer

	if tunDev != nil {
		go server.processPackets()
		log.Printf("TUN Device: %s", tunDev.Name())
	} else {
		log.Printf("TUN Device: disabled")
	}

	log.Printf("MASQUE VPN Server initialized")
	log.Printf("Listen Address: %s", server.Config.ListenAddr)
	log.Printf("VPN Network: %s", server.Config.AssignCIDR)
	log.Printf("Advertised Routes: %v", server.Config.AdvertiseRoutes)

	return server, nil
}

// Run запускает сервер
func (s *Server) Run(ctx context.Context) error {
	tlsConfig, err := s.setupTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to setup TLS: %w", err)
	}

	quicConf := &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  60 * time.Second,
		KeepAlivePeriod: 30 * time.Second,
	}

	// Временный режим для диагностики:
	// все HTTP/3 запросы напрямую идут в handleMASQUERequest,
	// без http.ServeMux, чтобы он не делал redirect 301.
	handler := http.HandlerFunc(s.handleMASQUERequest)

	server := &http3.Server{
		Addr:       s.Config.ListenAddr,
		Handler:    handler,
		TLSConfig:  tlsConfig,
		QUICConfig: quicConf,
	}

	log.Printf("MASQUE VPN Server listening on %s", s.Config.ListenAddr)
	log.Printf("API Server will start on %s", s.Config.APIServer.ListenAddr)

	go func() {
		if err := s.APIServer.Start(); err != nil {
			log.Printf("API Server error: %v", err)
		}
	}()

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.ListenAndServe()
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Printf("Shutting down server...")
		return server.Close()
	}
}

// handleHealthCheck обрабатывает запросы проверки здоровья
func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","service":"masque-vpn-server"}`))
}

// createMetricsHandler создает обработчик для метрик Prometheus
func (s *Server) createMetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Metrics endpoint"))
	})
}

// Close закрывает сервер и освобождает ресурсы
func (s *Server) Close() error {
	log.Printf("Closing MASQUE VPN Server...")

	s.IPPoolMu.Lock()
	for clientID, ip := range s.ClientIPMap {
		if session, exists := s.IPConnMap[ip]; exists {
			if session.Conn != nil {
				session.Conn.Close()
			}
		}
		log.Printf("Closed connection for client %s", clientID)
	}
	s.IPPoolMu.Unlock()

	if s.TunDev != nil {
		if err := s.TunDev.Close(); err != nil {
			log.Printf("Error closing TUN device: %v", err)
		}
		s.Metrics.TunInterfaceStatus.Set(0)
	}

	if s.APIServer != nil {
		if err := s.APIServer.Close(); err != nil {
			log.Printf("Error closing API server: %v", err)
		}
	}

	log.Printf("MASQUE VPN Server closed")
	return nil
}
