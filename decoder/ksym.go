package decoder

import (
	"fmt"

	"ebpf_exporter/config"
	"ebpf_exporter/util"

	"github.com/iovisor/gobpf/pkg/ksym"
)

// KSym is a decoder that transforms kernel address to a function name
type KSym struct {
	cache map[string][]byte
}

// Decode transforms kernel address to a function name
func (k *KSym) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	if k.cache == nil {
		k.cache = map[string][]byte{}
	}

	addr := fmt.Sprintf("%x", util.GetHostByteOrder().Uint64(in))

	if _, ok := k.cache[addr]; !ok {
		name, err := ksym.Ksym(addr)
		if err != nil {
			return []byte(fmt.Sprintf("unknown_addr:0x%s", addr)), nil
		}

		k.cache[addr] = []byte(name)
	}

	return k.cache[addr], nil
}
