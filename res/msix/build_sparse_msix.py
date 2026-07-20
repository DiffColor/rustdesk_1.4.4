#!/usr/bin/env python3

import argparse
import re
import xml.etree.ElementTree as ET
from pathlib import Path


PACKAGE_NAME = "RustDesk.WebIdentity"
PUBLISHER = "CN=RustDesk"
APPLICATION_ID = "RustDesk"
EXECUTABLE_NAME = "RustDesk.exe"
DISPLAY_NAME = "RustDesk"
PUBLISHER_DISPLAY_NAME = "RustDesk"
MIN_WINDOWS_VERSION = "10.0.19041.0"
MAX_TESTED_WINDOWS_VERSION = "10.0.26100.0"

FOUNDATION_NS = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
UAP_NS = "http://schemas.microsoft.com/appx/manifest/uap/windows10"
UAP3_NS = "http://schemas.microsoft.com/appx/manifest/uap/windows10/3"
UAP10_NS = "http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
RESCAP_NS = (
    "http://schemas.microsoft.com/appx/manifest/foundation/windows10/"
    "restrictedcapabilities"
)

ET.register_namespace("", FOUNDATION_NS)
ET.register_namespace("uap", UAP_NS)
ET.register_namespace("uap3", UAP3_NS)
ET.register_namespace("uap10", UAP10_NS)
ET.register_namespace("rescap", RESCAP_NS)


def normalize_version(value: str) -> str:
    value = value.strip().removeprefix("v")
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[.-](\d+))?", value)
    if match is None:
        raise ValueError(f"Invalid MSIX version: {value}")
    parts = [int(part or 0) for part in match.groups()]
    if any(part > 65535 for part in parts):
        raise ValueError(f"MSIX version component exceeds 65535: {value}")
    return ".".join(str(part) for part in parts)


def validate_web_host(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not value or "://" in value or "/" in value or ":" in value:
        raise ValueError(f"Expected a hostname without scheme, port, or path: {value}")
    labels = value.split(".")
    if any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError(f"Invalid hostname: {value}")
    return value


def _sub(parent: ET.Element, namespace: str, tag: str, **attributes: str) -> ET.Element:
    return ET.SubElement(parent, f"{{{namespace}}}{tag}", attributes)


def render_manifest(version: str, web_host: str, executable: str = EXECUTABLE_NAME) -> str:
    version = normalize_version(version)
    web_host = validate_web_host(web_host)

    package = ET.Element(
        f"{{{FOUNDATION_NS}}}Package",
        {"IgnorableNamespaces": "uap uap3 uap10 rescap"},
    )
    _sub(
        package,
        FOUNDATION_NS,
        "Identity",
        Name=PACKAGE_NAME,
        Publisher=PUBLISHER,
        Version=version,
        ProcessorArchitecture="neutral",
    )

    properties = _sub(package, FOUNDATION_NS, "Properties")
    _sub(properties, FOUNDATION_NS, "DisplayName").text = DISPLAY_NAME
    _sub(properties, FOUNDATION_NS, "PublisherDisplayName").text = (
        PUBLISHER_DISPLAY_NAME
    )
    _sub(properties, FOUNDATION_NS, "Logo").text = "Assets\\storelogo.png"
    _sub(properties, UAP10_NS, "AllowExternalContent").text = "true"

    resources = _sub(package, FOUNDATION_NS, "Resources")
    _sub(resources, FOUNDATION_NS, "Resource", Language="en-us")

    dependencies = _sub(package, FOUNDATION_NS, "Dependencies")
    _sub(
        dependencies,
        FOUNDATION_NS,
        "TargetDeviceFamily",
        Name="Windows.Desktop",
        MinVersion=MIN_WINDOWS_VERSION,
        MaxVersionTested=MAX_TESTED_WINDOWS_VERSION,
    )

    capabilities = _sub(package, FOUNDATION_NS, "Capabilities")
    _sub(capabilities, RESCAP_NS, "Capability", Name="runFullTrust")
    _sub(capabilities, RESCAP_NS, "Capability", Name="unvirtualizedResources")

    applications = _sub(package, FOUNDATION_NS, "Applications")
    application = _sub(
        applications,
        FOUNDATION_NS,
        "Application",
        Id=APPLICATION_ID,
        Executable=executable,
        **{
            f"{{{UAP10_NS}}}TrustLevel": "mediumIL",
            f"{{{UAP10_NS}}}RuntimeBehavior": "win32App",
        },
    )
    _sub(
        application,
        UAP_NS,
        "VisualElements",
        AppListEntry="none",
        DisplayName=DISPLAY_NAME,
        Description="RustDesk",
        BackgroundColor="transparent",
        Square150x150Logo="Assets\\Square150x150Logo.png",
        Square44x44Logo="Assets\\Square44x44Logo.png",
    )
    extensions = _sub(application, FOUNDATION_NS, "Extensions")
    extension = _sub(
        extensions,
        UAP3_NS,
        "Extension",
        Category="windows.appUriHandler",
    )
    handler = _sub(extension, UAP3_NS, "AppUriHandler")
    _sub(handler, UAP3_NS, "Host", Name=web_host)

    ET.indent(package, space="  ")
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(
        package, encoding="unicode"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the RustDesk sparse MSIX manifest")
    parser.add_argument("--version", required=True)
    parser.add_argument("--web-host", required=True)
    parser.add_argument("--executable", default=EXECUTABLE_NAME)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        render_manifest(version=args.version, web_host=args.web_host, executable=args.executable),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
