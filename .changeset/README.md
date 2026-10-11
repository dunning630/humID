# Changesets

Every pull request that changes a module adds one small file here:

```
npx changeset
```

Pick only the modules you changed and the bump (patch / minor / major). On
merge, `npm run version-modules` bumps exactly those modules, updates their
CHANGELOGs, and leaves every other module's version alone.

The native plugin (`plugins/humid-gate`) is a Rust crate and is versioned in
its own `Cargo.toml`; see RELEASING.md.
