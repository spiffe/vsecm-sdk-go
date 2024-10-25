![VSecM Logo](https://vsecm.com/vsecm.png)

## VMware Secrets Manager Go SDK

VMware Secrets Manager Go SDK is a Go client library for accessing the
VMware Secrets Manager API. It is a part of the 
[VMware Secrets Manager](https://vsecm.com/) project.

## Quick Start

You can use the SDK to interact with the VMware Secrets Manager API.

Here is a simple example to get started:

```go
package main

import (
  "fmt"
  "time"
  
  "github.com/spiffe/vsecm-sdk-go/sentry"
)

func main() {
  for {
    // Fetch the secret bound to this workload
    // using VMware Secrets Manager Go SDK:
    data, err := sentry.Fetch()

    if err != nil {
      fmt.Println("Failed. Will retry...")
    } else {
      fmt.Println("secret: '", data, "'")
    }

    time.Sleep(5 * time.Second)
  }
}
```

If your application is configured to consume secrets from VMware Secrets Manager,
then the above code will fetch the secret bound to the workload every 5 seconds.

Here is a sample `Deployment` manifest for the above code:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: example
  namespace: default
  labels:
    app.kubernetes.io/name: example
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: example
  template:
    metadata:
      labels:
        app.kubernetes.io/name: example
    spec:
      serviceAccountName: example
      containers:
      - name: main
        image: vsecm/example-using-sdk-go:latest
        volumeMounts:
        - name: spire-agent-socket
          mountPath: /spire-agent-socket
          readOnly: true
        env:
        - name: SPIFFE_ENDPOINT_SOCKET
          value: unix:///spire-agent-socket/spire-agent.sock
      volumes:
      - name: spire-agent-socket
        csi:
          driver: "csi.spiffe.io"
          readOnly: true
```

## Documentation

For more information about **VMware Secrets Manager** Go SDK,
see the [official documentation][ducks].

[ducks]: https://vsecm.com/documentation/usage/sdk/

## Project Structure

This project uses a slimmed down versions of the parent project's codebase.

* `./sdk/core/*` is a slimmed-down copy of the parent project's `./core/*`.
* `./sdk/lib/*` is a slimmed-down copy of the parent project's `./lib/*`.

* `./sentry` and `/.startup` are the main entry points for the SDK.

## Why Copy the Codebase?

As the Go experts say: "*A little copying is better than a little dependency.*"

The reason we copied the codebase is to keep the SDK self-contained and 
isolated.

## Contributing

Follow the main project's [contribution guidelines][contributing].

[contributing]: CONTRIBUTING.md

## Code of Conduct

VMware Go SDK follows [SPIFFE Code of Conduct][coc]

[coc]: https://github.com/spiffe/spiffe/blob/main/CODE-OF-CONDUCT.md

## License

[Apache 2.0](LICENSE).
