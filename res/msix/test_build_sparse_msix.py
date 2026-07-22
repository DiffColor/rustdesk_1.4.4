import importlib.util
import struct
import sys
import tempfile
import types
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock


SCRIPT_PATH = Path(__file__).with_name("build_sparse_msix.py")
JOB_SCRIPT_PATH = Path(__file__).parents[1] / "job.py"
PORTABLE_SCRIPT_PATH = Path(__file__).parents[2] / "libs/portable/generate.py"
RUNNER_MANIFEST_PATH = Path(__file__).parents[2] / "flutter/windows/runner/runner.exe.manifest"
REPO_ROOT = Path(__file__).parents[2]


def load_module():
    spec = importlib.util.spec_from_file_location("build_sparse_msix", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_job_module():
    spec = importlib.util.spec_from_file_location("job", JOB_SCRIPT_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_portable_module():
    brotli = types.ModuleType("brotli")
    setattr(brotli, "compress", lambda content, quality: content)
    previous_brotli = sys.modules.get("brotli")
    sys.modules["brotli"] = brotli
    spec = importlib.util.spec_from_file_location("portable_generate", PORTABLE_SCRIPT_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    try:
        spec.loader.exec_module(module)
    finally:
        if previous_brotli is None:
            sys.modules.pop("brotli", None)
        else:
            sys.modules["brotli"] = previous_brotli
    return module


class SparseMsixManifestTests(unittest.TestCase):
    def test_portable_payload_can_exclude_failed_identity_outputs(self):
        portable = load_portable_module()
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "rustdesk.exe").write_bytes(b"app")
            Path(folder, "rustdesk-web-identity.msix").write_bytes(b"partial")
            table = portable.generate_md5_table(
                folder, 1, ["rustdesk-web-identity.msix"]
            )
        self.assertIn("./rustdesk.exe", table)
        self.assertNotIn("./rustdesk-web-identity.msix", table)

    def test_remote_signing_preserves_existing_pe_signatures(self):
        job = load_job_module()
        pe = bytearray(512)
        pe[0:2] = b"MZ"
        struct.pack_into("<I", pe, 0x3C, 0x80)
        pe[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<H", pe, 0x98, 0x20B)
        struct.pack_into("<II", pe, 0x98 + 112 + 32, 0x180, 0x40)
        struct.pack_into("<IHH", pe, 0x180, 0x40, 0x0200, 0x0002)
        with tempfile.NamedTemporaryFile(suffix=".dll") as signed:
            signed.write(pe)
            signed.flush()
            self.assertTrue(job.has_embedded_pe_signature(signed.name))
            with mock.patch.object(job.shutil, "which", return_value="pwsh"), mock.patch.object(
                job.subprocess, "run", return_value=types.SimpleNamespace(returncode=0)
            ) as run:
                self.assertTrue(job.has_valid_pe_signature(signed.name))
                self.assertEqual(run.call_args.kwargs["timeout"], 30)
            with mock.patch.object(job.shutil, "which", return_value="pwsh"), mock.patch.object(
                job.subprocess, "run", return_value=types.SimpleNamespace(returncode=1)
            ):
                self.assertFalse(job.has_valid_pe_signature(signed.name))

        struct.pack_into("<IHH", pe, 0x180, 0, 0, 0)
        with tempfile.NamedTemporaryFile(suffix=".dll") as malformed:
            malformed.write(pe)
            malformed.flush()
            self.assertFalse(job.has_embedded_pe_signature(malformed.name))
            self.assertFalse(job.has_valid_pe_signature(malformed.name))

    def test_normalizes_tag_versions_to_msix_four_part_version(self):
        module = load_module()

        self.assertEqual(module.normalize_version("v1.4.4"), "1.4.4.0")
        self.assertEqual(module.normalize_version("1.4.4-11"), "1.4.4.11")
        self.assertEqual(module.normalize_version("1.4.4.62"), "1.4.4.62")

    def test_rejects_invalid_or_out_of_range_versions(self):
        module = load_module()

        for version in ("1.4", "1.4.beta", "1.4.4.70000"):
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    module.normalize_version(version)

    def test_renders_sparse_identity_and_verified_web_relationship(self):
        module = load_module()
        self.assertEqual(module.PACKAGE_NAME, "RustDesk.WebIdentity")
        self.assertEqual(module.PUBLISHER, "CN=RustDesk")

        manifest = module.render_manifest(
            version="1.4.4-11",
            web_host="example.com",
        )
        root = ET.fromstring(manifest)
        ns = {
            "f": "http://schemas.microsoft.com/appx/manifest/foundation/windows10",
            "uap3": "http://schemas.microsoft.com/appx/manifest/uap/windows10/3",
            "uap10": "http://schemas.microsoft.com/appx/manifest/uap/windows10/10",
        }

        identity = root.find("f:Identity", ns)
        self.assertIsNotNone(identity)
        self.assertEqual(identity.attrib["Name"], module.PACKAGE_NAME)
        self.assertEqual(identity.attrib["Publisher"], module.PUBLISHER)
        self.assertEqual(identity.attrib["Version"], "1.4.4.11")

        application = root.find("f:Applications/f:Application", ns)
        self.assertIsNotNone(application)
        self.assertEqual(application.attrib["Id"], module.APPLICATION_ID)
        self.assertEqual(application.attrib["Executable"], module.EXECUTABLE_NAME)

        host = root.find(
            ".//uap3:Extension[@Category='windows.appUriHandler']"
            "/uap3:AppUriHandler/uap3:Host",
            ns,
        )
        self.assertIsNotNone(host)
        self.assertEqual(host.attrib["Name"], "example.com")

        allow_external = root.find("f:Properties/uap10:AllowExternalContent", ns)
        self.assertIsNotNone(allow_external)
        self.assertEqual(allow_external.text, "true")

    def test_rejects_web_host_with_scheme_or_path(self):
        module = load_module()

        for host in ("https://example.com", "example.com/path", ""):
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    module.render_manifest(version="1.4.4", web_host=host)

    def test_runner_manifest_identity_matches_sparse_package(self):
        module = load_module()
        root = ET.parse(RUNNER_MANIFEST_PATH).getroot()
        msix = root.find("{urn:schemas-microsoft-com:msix.v1}msix")

        self.assertIsNotNone(msix)
        self.assertEqual(msix.attrib["publisher"], module.PUBLISHER)
        self.assertEqual(msix.attrib["packageName"], module.PACKAGE_NAME)
        self.assertEqual(msix.attrib["applicationId"], module.APPLICATION_ID)

    def test_sparse_identity_is_non_blocking_for_rustdesk(self):
        powershell = (Path(__file__).with_name("manage_sparse_identity.ps1")).read_text()
        core = (REPO_ROOT / "src/core_main.rs").read_text()
        windows = (REPO_ROOT / "src/platform/windows.rs").read_text()
        msi = (REPO_ROOT / "res/msi/Package/Components/RustDesk.wxs").read_text()
        msi_preprocess = (REPO_ROOT / "res/msi/preprocess.py").read_text()
        signing = (Path(__file__).with_name("sign_windows_files.ps1")).read_text()

        self.assertNotIn("-ForceApplicationShutdown", powershell)
        install_branch = powershell.split('if ($Action -in @("Provision", "Install"))', 1)[1].split(
            "} else {", 1
        )[0]
        self.assertEqual(install_branch.count("Remove-IdentityPackage"), 2)
        self.assertGreaterEqual(install_branch.count("Test-CurrentRequest"), 2)
        self.assertNotIn("std::process::exit(1)", core)
        self.assertEqual(core.count('#[cfg(windows)]\n                hbb_common::allow_err!(crate::platform::windows::manage_sparse_identity'), 3)
        self.assertIn('get_uninstall(false, false, false)', windows)
        self.assertIn('get_uninstall(kill_self, true, true)', windows)
        self.assertNotIn("parent().unwrap_or_default()", windows)
        self.assertIn('if unregister_sparse_identity {', windows)
        self.assertIn('.spawn()?', windows)
        self.assertIn('include_str!("../../res/msix/manage_sparse_identity.ps1")', windows)
        self.assertIn('"-EncodedCommand"', windows)
        self.assertIn("GzEncoder::new", windows)
        self.assertIn("[IO.MemoryStream]::new([byte[]]$b)", windows)
        self.assertNotIn("[IO.MemoryStream]::new(,$b)", windows)
        self.assertNotIn('"-File"', windows)
        self.assertIn('RustDesk\\\\web-identity', windows)
        self.assertNotIn('std::env::temp_dir().join(format!("rustdesk-sparse-identity-', windows)
        self.assertIn('Id="RegisterSparseIdentity"', msi)
        self.assertIn('Id="UnregisterSparseIdentity"', msi)
        self.assertIn('ExeCommand=" --provision-sparse-identity"', msi)
        self.assertIn('Execute="deferred" Impersonate="no"', msi)
        self.assertIn('Action="RemoveInstallFolder.SetParam" Before="TryStopDeleteService"', msi)
        self.assertIn('Action="TryStopDeleteService" Before="TerminateProcesses"', msi)
        self.assertIn('Action="TerminateProcesses" Before="TerminateBrokers"', msi)
        self.assertIn('Action="TerminateBrokers" Before="UnregisterSparseIdentity"', msi)
        self.assertIn('Action="UnregisterSparseIdentity" Before="RemoveInstallFolder"', msi)

        self.assertNotIn('"rustdesk-web-identity.msix"', msi_preprocess)
        self.assertNotIn('"rustdesk-web-identity.cer"', msi_preprocess)
        self.assertIn('$StateDirectory', powershell)
        self.assertIn('$env:ProgramData "RustDesk\\web-identity"', powershell)
        self.assertIn('Add-Content -LiteralPath $OwnershipPath', powershell)
        self.assertIn('Remove-OwnedCertificates', powershell)
        self.assertIn('Remove-ObsoleteOwnedCertificates', powershell)
        self.assertIn('[System.Threading.Mutex]::new', powershell)
        self.assertIn('"RustDesk.WebIdentity.Operation"', powershell)
        self.assertIn('$DesiredStatePath', powershell)
        self.assertIn('"$Action|$RequestId"', powershell)
        self.assertIn("$mutex.WaitOne()", powershell)
        self.assertIn("StoreName]::Root", powershell)
        self.assertIn("StoreLocation]::LocalMachine", powershell)
        self.assertNotIn("StoreLocation]::CurrentUser", powershell)
        self.assertIn("CertificateAuthority", powershell)
        self.assertIn('"--register-sparse-identity"', core)
        self.assertIn('Some("--tray")', core)
        self.assertIn("reconcile_sparse_identity_for_current_user", core)
        self.assertIn("Get-AppxPackage -AllUsers", powershell)
        self.assertIn("Remove-AppxPackage -AllUsers", powershell)
        self.assertIn("ExpectedRootSha256", powershell)
        self.assertIn("ExpectedSignerSha256", powershell)
        self.assertIn("Get-AuthenticodeSignature -FilePath $Path", powershell)
        self.assertIn("signed RustDesk runtime pin", powershell)
        self.assertIn('[ValidateSet("Provision", "Install", "Uninstall")]', powershell)
        self.assertIn('$Action -eq "Provision"', powershell)
        self.assertIn('args[0] == "--provision-sparse-identity"', core)
        self.assertIn('option_env!("RUSTDESK_IDENTITY_ROOT_SHA256")', windows)
        self.assertIn('option_env!("RUSTDESK_IDENTITY_SIGNER_SHA256")', windows)
        self.assertNotIn("Remove-Item -LiteralPath $DesiredStatePath", powershell)
        self.assertNotIn("Remove-Item -LiteralPath $StateDirectory", powershell)
        self.assertLess(
            powershell.index("Add-OwnedCertificate -Thumbprint $certificate.Thumbprint"),
            powershell.index("Add-TrustRootCertificate -Certificate $certificate"),
        )
        self.assertIn("copy_sparse_identity_commands(src_dir, &path)", windows)
        self.assertIn('start \\"\\" /b \\"{exe}\\" --register-sparse-identity', windows)
        self.assertIn('@(".dll", ".exe", ".msi")', signing)
        self.assertNotIn('".sys"', signing)
        self.assertIn("/tr $timestampUrl /td SHA256", signing)
        self.assertIn('@("http://timestamp.sectigo.com", "http://timestamp.digicert.com")', signing)
        self.assertIn("GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256)", signing)
        self.assertIn("signed runtime signer pin", signing)
        self.assertIn("signed runtime root pin", signing)
        self.assertIn("X509ChainTrustMode]::CustomRootTrust", signing)
        self.assertIn("0x800B010A", signing)
        self.assertIn("A certificate chain could not be built to a trusted root authority", signing)
        self.assertIn("$expectedChainBuildTrustFailure", signing)
        self.assertIn('$signature.Status -eq "UnknownError"', signing)
        self.assertIn('$signature.Status -eq "Valid"', signing)
        self.assertIn("$signature.TimeStamperCertificate", signing)
        self.assertNotIn("$expectedLegacyRootTrustFailure", signing)
        self.assertIn("Timestamp Verified by:", signing)
        self.assertIn("Windows signing temporary-file cleanup was incomplete", signing)
        self.assertIn("Windows signing trust cleanup was incomplete", signing)
        self.assertIn("Unexpected SignTool verification failure", signing)
        self.assertIn("RFC3161 timestamp verification failed", signing)
        self.assertIn("Unexpected Authenticode signature count", signing)
        self.assertNotIn("Cert:\\CurrentUser\\Root", signing)
        self.assertIn("$expectedSignerMarker", signing)
        self.assertIn("$KeepTrust", signing)
        self.assertIn("Preserved existing signature", signing)
        self.assertIn("Existing signature is invalid", signing)

        for workflow_name in ("flutter-build.yml", "flutter-build-windows.yml"):
            workflow = (REPO_ROOT / ".github/workflows" / workflow_name).read_text()
            self.assertLess(
                workflow.index("- name: Prepare runtime sparse identity pins"),
                workflow.index("- name: Build rustdesk"),
            )
            self.assertIn("RUSTDESK_IDENTITY_ROOT_SHA256=$rootHash", workflow)
            self.assertIn("RUSTDESK_IDENTITY_SIGNER_SHA256=$signerHash", workflow)
            self.assertIn("SHA256]::HashData($root[0].RawData)", workflow)
            self.assertIn("$data.OtherCertificates | Where-Object", workflow)
            self.assertIn("$data.EndEntityCertificates | Where-Object", workflow)
            self.assertIn("X509ChainTrustMode]::CustomRootTrust", workflow)
            self.assertIn("Sparse identity signer does not chain to the expected root", workflow)
            step = workflow.split("- name: Build and sign sparse MSIX identity packages", 1)[1]
            self.assertNotIn("continue-on-error: true", step.split("- name:", 1)[0])
            self.assertIn("timeout-minutes: 5", step.split("- name:", 1)[0])
            self.assertIn("--version $env:TAG_NAME", step.split("- name:", 1)[0])
            self.assertIn("--web-host $env:IDENTITY_WEB_HOST", step.split("- name:", 1)[0])
            self.assertIn("$env:TAG_NAME -notmatch", step.split("try {", 1)[0])
            self.assertIn("'^v?\\d+\\.\\d+\\.\\d+(?:[.-]\\d+)?$'", step)
            self.assertIn("Get-PfxData -FilePath $pfxPath -Password $securePassword", step)
            self.assertIn("Import-Certificate -FilePath $signerCerPath", step)
            self.assertIn("Sparse MSIX PFX must contain exactly one end-entity certificate", step)
            self.assertIn("Sparse MSIX PFX must contain exactly one self-issued CA root certificate", step)
            self.assertIn("Sparse MSIX signer does not match the runtime signer pin", step)
            self.assertIn("Sparse MSIX root does not match the runtime root pin", step)
            self.assertIn("Sparse MSIX signer does not chain to the bundled root certificate", step)
            self.assertIn("X509ChainTrustMode]::CustomRootTrust", step)
            self.assertIn("Export-Certificate -Cert $rootCert -FilePath $cerPath", step)
            self.assertIn("Export-Certificate -Cert $cert -FilePath $signerCerPath", step)
            self.assertNotIn("manage_sparse_identity.ps1", step)
            self.assertIn("Join-Path $env:RUNNER_TEMP", step)
            self.assertIn('$cert.Subject -ne "CN=RustDesk"', step)
            self.assertNotIn("$expectedLegacyRootTrustFailure", step)
            final_verify = workflow.split("- name: Verify Windows release signatures", 1)[1]
            self.assertIn("0x800B010A", final_verify)
            self.assertIn("$expectedChainBuildTrustFailure", final_verify)
            self.assertIn("$validSignature", final_verify)
            self.assertIn("$signature.TimeStamperCertificate", final_verify)
            self.assertNotIn("$expectedLegacyRootTrustFailure", final_verify)
            self.assertIn("$signature.SignerCertificate.Thumbprint -ne $cert.Thumbprint", step)
            self.assertIn("/tr $timestampUrl /td SHA256", step)
            self.assertIn("MSIX RFC3161 timestamp verification failed", step)
            self.assertIn("try {", step)
            self.assertIn("} finally {", step)
            self.assertIn('if (-not $succeeded)', step)
            self.assertIn("- name: Clean sparse MSIX signing material", step)
            self.assertIn("if: always()", step)
            self.assertIn("identity-build-complete", step)
            self.assertIn("Where-Object { $_.Name -match '^\\d+\\.\\d+\\.\\d+\\.\\d+$'", step)
            self.assertNotIn("Sort-Object Name -Descending | Select-Object -First 1", step)
            self.assertIn("- name: Sign Windows payload with identity certificate", workflow)
            self.assertIn("- name: Sign Windows release files with identity certificate", workflow)
            self.assertIn('-Paths @("SignOutput") -ReplaceExisting -KeepTrust', workflow)
            self.assertIn("- name: Verify Windows release signatures", workflow)
            self.assertIn("sign_windows_files.ps1", workflow)
            self.assertIn("WINDOWS_IDENTITY_PFX_BASE64", workflow)
            self.assertIn("Windows release RFC3161 timestamp verification failed", workflow)
            self.assertIn('$expectedChainBuildTrustFailure = $allowUntrustedRoot', workflow)
            self.assertIn('$signature.Status -eq "UnknownError"', workflow)
            self.assertIn('$signature.Status -eq "Valid"', workflow)
            self.assertIn("Number of signatures successfully Verified: 1", workflow)
            self.assertNotIn("$expectedLegacyRootTrustFailure", workflow)
            self.assertIn("$signature.SignerCertificate.Thumbprint -ne $expectedThumbprint", workflow)
            self.assertIn("Expected fallback signer thumbprint is missing", workflow)
            publish = workflow.split("- name: Publish Release", 1)[1].split("\n\n", 1)[0]
            self.assertNotIn("rustdesk-*.exe", publish)
            self.assertNotIn("rustdesk-*.msi", publish)
            cleanup = workflow.split("- name: Clean Windows release signing material", 1)[1].split("- name:", 1)[0]
            self.assertNotIn("continue-on-error: true", cleanup)
            self.assertIn('throw "Windows release signing material cleanup was incomplete"', cleanup)
            self.assertNotIn("$rootCertMarker", cleanup)
            self.assertNotIn("Cert:\\CurrentUser\\Root", cleanup)
            self.assertLess(
                workflow.index("- name: Verify Windows release signatures"),
                workflow.index("- name: Publish Release"),
            )


if __name__ == "__main__":
    unittest.main()
