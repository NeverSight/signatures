# signatures

FLIRT-style signature libraries for [NeverD](https://github.com/NeverSight/NeverD).

## Layout

```
<format>/<arch>/<bitness>/*.pat
```

Supported formats: `elf`, `pe`, `macho`.

NeverD installs these files to `build/bin/signatures/` at build time. Use `neverd sigs --auto` to apply the matching set for the loaded binary.
