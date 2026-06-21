use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    // Generate the varlink management-interface bindings (async server + client)
    // into OUT_DIR; `manage::generated` includes the result.
    varlink_generator::cargo_build_options(
        "src/manage/co.0w0.etheripxdp.Management.varlink",
        &varlink_generator::GeneratorOptions {
            generate_async: true,
            ..Default::default()
        },
    );

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "etherip-xdp-ebpf")
        .ok_or_else(|| anyhow!("etherip-xdp-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
