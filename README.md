# socks
![Build Status](https://github.com/hupe1980/socks/workflows/build/badge.svg) 
[![Go Reference](https://pkg.go.dev/badge/github.com/hupe1980/socks.svg)](https://pkg.go.dev/github.com/hupe1980/socks)
> Golang socks proxy and dialer

:warning: This is experimental and subject to breaking changes.

## Usage
```golang
import (
	"log"

	"github.com/hupe1980/socks"
)

func main() {
	log.Fatal(socks.ListenAndServe(":1080")
}
```

### Documentation
See [godoc](https://pkg.go.dev/github.com/hupe1980/socks).

### Examples
See more complete [examples](https://github.com/hupe1980/socks/tree/main/examples).

## License
[MIT](LICENCE)
