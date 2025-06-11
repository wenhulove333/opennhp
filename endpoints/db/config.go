package db

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/utils"
	toml "github.com/pelletier/go-toml/v2"
)

var (
	baseConfigWatch     io.Closer
	serverConfigWatch   io.Closer
	consumerConfigWatch io.Closer
	resourceConfigWatch io.Closer

	errLoadConfig = fmt.Errorf("config load error")
)

type Config struct {
	LogLevel            int
	PrivateKeyBase64    string
	DefaultCipherScheme int `json:"defaultCipherScheme"`
	SymmetricCipherMode string `json:"symmetricCipherMode"`
	DbId                string `json:"dbId"`
}

type Peers struct {
	Servers []*core.UdpPeer
}

type Resources struct {
	Resources []*KnockResource
}

type Consumer struct {
	ConsumerID string
	TEEPublicKeyBase64 string `json:"teePublicKeyBase64"`
}

type Consumers struct {
	Consumers []*Consumer
}

func (a *UdpDevice) loadBaseConfig() error {
	// config.toml
	fileName := filepath.Join(ExeDirPath, "etc", "config.toml")
	if err := a.updateBaseConfig(fileName); err != nil {
		// report base config error
		return err
	}

	baseConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("base config: %s has been updated", fileName)
		a.updateBaseConfig(fileName)
	})
	return nil
}

func (a *UdpDevice) loadPeers() error {
	// server.toml
	fileName := filepath.Join(ExeDirPath, "etc", "server.toml")
	if err := a.updateServerPeers(fileName); err != nil {
		// ignore error
		_ = err
	}

	serverConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("server peer config: %s has been updated", fileName)
		a.updateServerPeers(fileName)
	})

	return nil
}

func (a *UdpDevice) loadConsumers() error {
	// consumer.toml
	fileName := filepath.Join(ExeDirPath, "etc", "consumer.toml")
	if err := a.updateConsumerConfig(fileName); err != nil {
		// ignore error
		_ = err
	}

	consumerConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("consumer peer config: %s has been updated", fileName)
	})

	return nil
}

func (a *UdpDevice) updateBaseConfig(file string) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	content, err := os.ReadFile(file)
	if err != nil {
		log.Error("failed to read base config: %v", err)
	}

	var conf Config
	if err := toml.Unmarshal(content, &conf); err != nil {
		log.Error("failed to unmarshal base config: %v", err)
	}
	if a.config == nil {
		a.config = &conf
		a.log.SetLogLevel(conf.LogLevel)
		return err
	}

	// update
	if a.config.LogLevel != conf.LogLevel {
		log.Info("set base log level to %d", conf.LogLevel)
		a.log.SetLogLevel(conf.LogLevel)
		a.config.LogLevel = conf.LogLevel
	}

	if a.config.DefaultCipherScheme != conf.DefaultCipherScheme {
		log.Info("set default cipher scheme to %d", conf.DefaultCipherScheme)
		a.config.DefaultCipherScheme = conf.DefaultCipherScheme
	}

	return err
}

func (a *UdpDevice) updateServerPeers(file string) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	content, err := os.ReadFile(file)
	if err != nil {
		log.Error("failed to read server peer config: %v", err)
	}

	// update
	var peers Peers
	serverPeerMap := make(map[string]*core.UdpPeer)
	if err := toml.Unmarshal(content, &peers); err != nil {
		log.Error("failed to unmarshal server config: %v", err)
	}
	for _, p := range peers.Servers {
		p.Type = core.NHP_DB
		a.device.AddPeer(p)
		serverPeerMap[p.PublicKeyBase64()] = p
	}

	// remove old peers from device
	a.serverPeerMutex.Lock()
	defer a.serverPeerMutex.Unlock()
	for pubKey := range a.serverPeerMap {
		if _, found := serverPeerMap[pubKey]; !found {
			a.device.RemovePeer(pubKey)
		}
	}
	a.serverPeerMap = serverPeerMap

	return err
}

func (a *UdpDevice) updateConsumerConfig(file string) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	content, err := os.ReadFile(file)
	if err != nil {
		log.Error("failed to read consumer config: %v", err)
	}

	var consumers Consumers
	if err := toml.Unmarshal(content, &consumers); err != nil {
		log.Error("failed to unmarshal consumer config: %v", err)
	}

	consumerMap := make(map[string]*Consumer)
	for _, consumer := range consumers.Consumers {
		consumerMap[consumer.ConsumerID] = consumer
	}

	a.consumerMutex.Lock()
	defer a.consumerMutex.Unlock()
	a.consumerMap = consumerMap

	return nil
}

func (a *UdpDevice) StopConfigWatch() {
	if baseConfigWatch != nil {
		baseConfigWatch.Close()
	}
	if serverConfigWatch != nil {
		serverConfigWatch.Close()
	}
	if resourceConfigWatch != nil {
		resourceConfigWatch.Close()
	}
	if consumerConfigWatch != nil {
		consumerConfigWatch.Close()
	}
}
