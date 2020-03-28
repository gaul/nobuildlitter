# nobuildlitter

This `LD_PRELOAD` library allows users to relocate build litter created by
`make`, `mvn`, `cargo`, etc. to another directory.  This is useful when the
source code directory uses cloud syncing, snapshotting, or is read-only.

## Usage

```
LD_PRELOAD=/path/to/libnobuildlitter.so make
```

## License

Copyright (C) 2020 Andrew Gaul

Licensed under the Apache License, Version 2.0
