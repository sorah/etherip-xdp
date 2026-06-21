//! Management plane: the `co.0w0.etheripxdp.Management` varlink interface (and,
//! in later modules, the `etherip-xdp-manager` proxy and the `etheripctl` CLI).

// Machine-generated varlink bindings (async server trait + client). All lints
// are silenced because the output is generated, not hand-written (it uses the
// varlink IDL's own camelCase/PascalCase identifiers verbatim).
#[allow(warnings, clippy::all)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/co.0w0.etheripxdp.Management.rs"));
}

pub mod discovery;
pub mod proxy;
