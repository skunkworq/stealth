// Package sniffer provides packet capture functionality using libpcap.
package sniffer

/*
#cgo LDFLAGS: -L${SRCDIR}/rust/target/release -lstealth_sniffer -lpcap -lm
#cgo CFLAGS: -I${SRCDIR}/rust/target/release

#include <stdlib.h>
#include <stdint.h>

typedef struct {
    long timestamp_sec;
    long timestamp_usec;
    char* source_ip;
    char* dest_ip;
    char* protocol;
    int length;
    char* info;
} PacketEventC;

typedef void (*PacketCallback)(PacketEventC*);

int start_sniffing(const char* device_name, PacketCallback callback);
void stop_sniffing();
void free_packet_event(PacketEventC* event);
char* get_default_device();
void free_string(char* s);

extern void goPacketCallback(PacketEventC* event);
*/
import "C"
import (
	"fmt"
	"time"
	"unsafe"
)

// Packet represents a captured network packet in Go
type Packet struct {
	Timestamp time.Time `json:"timestamp"`
	SourceIP  string    `json:"source_ip"`
	DestIP    string    `json:"dest_ip"`
	Protocol  string    `json:"protocol"`
	Length    int       `json:"length"`
	Info      string    `json:"info"`
}

var packetHandler func(Packet)

//export goPacketCallback
func goPacketCallback(event *C.PacketEventC) {
	if event == nil {
		return
	}

	// Convert C strings
	var src, dst, proto, info string
	if event.source_ip != nil {
		src = C.GoString(event.source_ip)
	}
	if event.dest_ip != nil {
		dst = C.GoString(event.dest_ip)
	}
	if event.protocol != nil {
		proto = C.GoString(event.protocol)
	}
	if event.info != nil {
		info = C.GoString(event.info)
	}

	ts := time.Unix(int64(event.timestamp_sec), int64(event.timestamp_usec)*1000)

	pkt := Packet{
		Timestamp: ts, // accurate mapping from epoch
		SourceIP:  src,
		DestIP:    dst,
		Protocol:  proto,
		Length:    int(event.length),
		Info:      info,
	}

	// Free C resources allocated heavily by Rust
	C.free_packet_event(event)

	if packetHandler != nil {
		packetHandler(pkt)
	}
}

// Start begins capturing packets on the specified interface
func Start(device string, handler func(Packet)) error {
	packetHandler = handler

	var cDevice *C.char
	if device == "" || device == "default" {
		cDevice = C.get_default_device()
		if cDevice == nil {
			return fmt.Errorf("no default capture device found")
		}
		defer C.free_string(cDevice)
	} else {
		cDevice = C.CString(device)
		defer C.free(unsafe.Pointer(cDevice))
	}

	res := C.start_sniffing(cDevice, (C.PacketCallback)(unsafe.Pointer(C.goPacketCallback)))
	if res != 0 {
		return fmt.Errorf("failed to start packet capture, err: %d", res)
	}

	return nil
}

// Stop halts packet capture
func Stop() {
	C.stop_sniffing()
}
