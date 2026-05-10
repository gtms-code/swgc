fn main() {
    // ── Copy wireguard.dll next to the exe for dev/debug mode ────────────
    // In production `tauri build` handles this via bundle.resources, but
    // during `cargo build` / `npm run tauri dev` the DLL is not copied
    // automatically.  We do it here so dev runs find the DLL without
    // falling back to the system WireGuard installation.
    let dll_src = std::path::PathBuf::from("wireguard.dll");
    if dll_src.exists() {
        let out_dir  = std::env::var("OUT_DIR").unwrap();
        let profile  = std::env::var("PROFILE").unwrap();
        // OUT_DIR = …/target/<profile>/build/swgc-<hash>/out
        // Walk up until we reach the directory named by PROFILE.
        if let Some(target_dir) = std::path::Path::new(&out_dir)
            .ancestors()
            .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(profile.as_str()))
        {
            let dll_dst = target_dir.join("wireguard.dll");
            if !dll_dst.exists() {
                if let Err(e) = std::fs::copy(&dll_src, &dll_dst) {
                    println!("cargo:warning=wireguard.dll コピー失敗: {e}");
                } else {
                    println!("cargo:warning=wireguard.dll → {dll_dst:?}");
                }
            }
        }
    }
    // Re-run this build script whenever wireguard.dll changes.
    println!("cargo:rerun-if-changed=wireguard.dll");


    let manifest = r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
</assembly>"#;

    tauri_build::try_build(
        tauri_build::Attributes::new().windows_attributes(
            tauri_build::WindowsAttributes::new().app_manifest(manifest),
        ),
    )
    .expect("failed to run tauri-build");
}
