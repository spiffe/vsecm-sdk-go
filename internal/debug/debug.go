package debug

import (
	"log"

	"github.com/spiffe/vsecm-sdk-go/internal/config"
)

func Log(args ...any) {
	if config.SdkConfig.Debug {
		log.Println(args...)
	}
}
