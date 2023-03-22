package decoder

import (
	"ebpf_exporter/config"
	"ebpf_exporter/util"
	"fmt"
)

type Syscall struct{}

func (s *Syscall) Decode(in []byte, conf config.Decoder) ([]byte, error) {
	byteOrder := util.GetHostByteOrder()

	result := uint64(0)

	switch len(in) {
	case 8:
		result = byteOrder.Uint64(in)
	case 4:
		result = uint64(byteOrder.Uint32(in))
	case 2:
		result = uint64(byteOrder.Uint16(in))
	case 1:
		result = uint64(in[0])
	default:
		return nil, fmt.Errorf("unknown value length %d for %#v", len(in), in)
	}

	return []byte(util.GetSyscall(result)), nil
}
