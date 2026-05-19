// Package events provides a lightweight pub/sub signal bus for crawl pipeline events.
package events

import (
	"context"
	"fmt"
	"sync"
)

type Signal any

type Sender interface {
	Send(signal Signal)
}

type Receiver interface {
	Receive(signal Signal)
}

type SignalHandler func(signal Signal)

type Handler struct {
	ID   string
	Func SignalHandler
}

type Manager struct {
	mu        sync.RWMutex
	receivers map[Signal][]Receiver
	handlers  map[string][]Handler
}

func NewManager() *Manager {
	return &Manager{
		receivers: make(map[Signal][]Receiver),
		handlers:  make(map[string][]Handler),
	}
}

func (m *Manager) Connect(receiver Receiver, signals ...Signal) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, sig := range signals {
		m.receivers[sig] = append(m.receivers[sig], receiver)
	}
}

func (m *Manager) Disconnect(receiver Receiver) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for sig, receivers := range m.receivers {
		for i := len(receivers) - 1; i >= 0; i-- {
			if receivers[i] == receiver {
				m.receivers[sig] = append(receivers[:i], receivers[i+1:]...)
			}
		}
	}
}

func (m *Manager) ConnectHandler(name string, handler SignalHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[name] = append(m.handlers[name], Handler{
		ID:   fmt.Sprintf("%p", handler),
		Func: handler,
	})
}

func (m *Manager) DisconnectHandler(name string, handler SignalHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()

	handlers := m.handlers[name]
	handlerID := fmt.Sprintf("%p", handler)
	for i := len(handlers) - 1; i >= 0; i-- {
		if handlers[i].ID == handlerID {
			m.handlers[name] = append(handlers[:i], handlers[i+1:]...)
		}
	}
}

func (m *Manager) Send(signal Signal) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if receivers, ok := m.receivers[signal]; ok {
		for _, receiver := range receivers {
			receiver.Receive(signal)
		}
	}

	signalName := getSignalName(signal)
	if handlers, ok := m.handlers[signalName]; ok {
		for _, handler := range handlers {
			handler.Func(signal)
		}
	}
}

func (m *Manager) SendCtx(_ context.Context, signal Signal) {
	m.Send(signal)
}

func getSignalName(signal Signal) string {
	return fmt.Sprintf("%T", signal)
}
