import importlib.util
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


SCRIPT_PATH = Path(__file__).with_name("build_sparse_msix.py")
RUNNER_MANIFEST_PATH = Path(__file__).parents[2] / "flutter/windows/runner/runner.exe.manifest"
REPO_ROOT = Path(__file__).parents[2]


def load_module():
    spec = importlib.util.spec_from_file_location("build_sparse_msix", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class SparseMsixManifestTests(unittest.TestCase):
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

        manifest = module.render_manifest(
            version="1.4.4-11",
            web_host="mendhands.pages.dev",
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
        self.assertEqual(host.attrib["Name"], "mendhands.pages.dev")

        allow_external = root.find("f:Properties/uap10:AllowExternalContent", ns)
        self.assertIsNotNone(allow_external)
        self.assertEqual(allow_external.text, "true")

    def test_rejects_web_host_with_scheme_or_path(self):
        module = load_module()

        for host in ("https://mendhands.pages.dev", "mendhands.pages.dev/path", ""):
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

        self.assertNotIn("-ForceApplicationShutdown", powershell)
        install_branch = powershell.split('if ($Action -eq "Install")', 1)[1].split(
            "} else {", 1
        )[0]
        self.assertEqual(install_branch.count("Remove-IdentityPackage"), 2)
        self.assertGreaterEqual(install_branch.count("Test-CurrentRequest"), 2)
        self.assertNotIn("std::process::exit(1)", core)
        self.assertEqual(core.count('#[cfg(windows)]\n                hbb_common::allow_err!(crate::platform::windows::manage_sparse_identity'), 2)
        self.assertIn('get_uninstall(false, false, false)', windows)
        self.assertIn('get_uninstall(kill_self, true, true)', windows)
        self.assertIn('if unregister_sparse_identity {', windows)
        self.assertIn('.spawn()?', windows)
        self.assertIn('include_str!("../../res/msix/manage_sparse_identity.ps1")', windows)
        self.assertIn('rustdesk-sparse-identity', windows)
        self.assertNotIn('std::env::temp_dir().join(format!("rustdesk-sparse-identity-', windows)
        self.assertNotIn('Id="RegisterSparseIdentity"', msi)
        self.assertNotIn('Id="UnregisterSparseIdentity"', msi)
        self.assertIn('"mendhands-rustdesk-identity.msix"', msi_preprocess)
        self.assertIn('file_path.name.lower() in g_excluded_payloads', msi_preprocess)
        self.assertIn('$StateDirectory', powershell)
        self.assertIn('Add-Content -LiteralPath $OwnershipPath', powershell)
        self.assertIn('Remove-OwnedCertificates', powershell)
        self.assertIn('Remove-ObsoleteOwnedCertificates', powershell)
        self.assertIn('[System.Threading.Mutex]::new', powershell)
        self.assertIn('"MendHands.RustDesk.SparseIdentity"', powershell)
        self.assertIn('$DesiredStatePath', powershell)
        self.assertIn('"$Action|$RequestId"', powershell)
        self.assertIn("$mutex.WaitOne()", powershell)
        self.assertNotIn("Remove-Item -LiteralPath $DesiredStatePath", powershell)
        self.assertNotIn("Remove-Item -LiteralPath $StateDirectory", powershell)
        self.assertLess(
            powershell.index("Add-OwnedCertificate -Thumbprint $certificate.Thumbprint"),
            powershell.index("$certificateAdded = Add-TrustedPeopleCertificate"),
        )
        self.assertNotIn("FromBase64String('{script}')", windows)
        self.assertIn("encoded_command.len() > 30_000", windows)

        for workflow_name in ("flutter-build.yml", "flutter-build-windows.yml"):
            workflow = (REPO_ROOT / ".github/workflows" / workflow_name).read_text()
            step = workflow.split("- name: Build and sign sparse MSIX identity packages", 1)[1]
            self.assertIn("continue-on-error: true", step.split("- name:", 1)[0])
            self.assertIn("timeout-minutes: 5", step.split("- name:", 1)[0])
            self.assertIn("--version $env:TAG_NAME", step.split("- name:", 1)[0])
            self.assertIn("$env:TAG_NAME -notmatch", step.split("try {", 1)[0])
            self.assertIn("'^v?\\d+\\.\\d+\\.\\d+(?:[.-]\\d+)?$'", step)
            self.assertIn("Get-PfxData -FilePath $pfxPath -Password $securePassword", step)
            self.assertIn("Import-Certificate -FilePath $cerPath", step)
            self.assertIn("Join-Path $env:RUNNER_TEMP", step)
            self.assertIn('$cert.Subject -ne "CN=MendHands"', step)
            self.assertIn("$signature.SignerCertificate.Thumbprint -ne $cert.Thumbprint", step)
            self.assertIn("try {", step)
            self.assertIn("} finally {", step)
            self.assertIn('if (-not $succeeded)', step)
            self.assertNotIn('Copy-Item res\\msix\\manage_sparse_identity.ps1', step)
            self.assertIn("- name: Clean sparse MSIX signing material", step)
            self.assertIn("if: always()", step)
            self.assertIn("identity-build-complete", step)


if __name__ == "__main__":
    unittest.main()
