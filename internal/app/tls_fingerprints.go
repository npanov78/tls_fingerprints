package app

import (
	"log"
	src "nir_fingerprints/internal/services"
	"os"
	"sync"
)

func Start() {
	entries, err := os.ReadDir("pcaps")
	if err != nil {
		log.Fatal(err)
	}
	numEntries := len(entries)
	if numEntries == 0 {
		log.Fatal("No pcap files found in ./pcaps folder")
	}

	wg := new(sync.WaitGroup)
	wg.Add(numEntries)
	for _, e := range entries {
		log.Printf("Processing pcaps/%s file...\n\n", e.Name())
		go src.ProcessPCAP("pcaps/"+e.Name(), wg)
	}
	wg.Wait()
}
