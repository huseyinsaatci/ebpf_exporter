package exporter

import (
	"ebpf_exporter/config"
	"log"

	"github.com/aquasecurity/libbpfgo"
)

func attachModule(module *libbpfgo.Module, cfg config.Config) (map[*libbpfgo.BPFProg]bool, error) {
	attached := map[*libbpfgo.BPFProg]bool{}

	iter := module.Iterator()
	for {
		prog := iter.NextProgram()
		if prog == nil {
			break
		}

		var err error
		if cfg.Metrics.IsXDP {
			for i := 0; i < len(cfg.Metrics.Interfaces); i++ {
				_, err = prog.AttachXDP(cfg.Metrics.Interfaces[i])
				if err != nil {
					break
				}
			}
		} else {
			_, err = prog.AttachGeneric()
		}

		if err != nil {
			log.Printf("Failed to attach program %q for config %q: %v", prog.Name(), cfg.Name, err)
			attached[prog] = false
		} else {
			attached[prog] = true
		}
	}

	return attached, nil
}
