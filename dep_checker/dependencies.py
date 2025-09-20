"""A list of dependencies, including their CPE, names and keywords for querying different vulnerability databases"""

from typing import Optional, Callable
from pathlib import Path
import versions_parser as vp


class CPE:
    def __init__(self, vendor: str, product: str):
        self.vendor = vendor
        self.product = product


class Dependency:
    def __init__(
        self,
        version_parser: Callable[[Path], str],
        cpe: Optional[CPE] = None,
        npm_name: Optional[str] = None,
        keyword: Optional[str] = None,
    ):
        self.version_parser = version_parser
        self.cpe = cpe
        self.npm_name = npm_name
        self.keyword = keyword

    def get_cpe(self, repo_path: Path) -> Optional[str]:
        if self.cpe:
            return f"cpe:2.3:a:{self.cpe.vendor}:{self.cpe.product}:{self.version_parser(repo_path)}:*:*:*:*:*:*:*"
        else:
            return None


ignore_list: list[str] = [
    "CVE-2018-25032",  # zlib, already fixed in the fork Node uses (Chromium's)
    "CVE-2007-5536",  # openssl, old and only in combination with HP-UX
    "CVE-2019-0190",  # openssl, can be only triggered in combination with Apache HTTP Server version 2.4.37
]

# Define common dependencies used in all branches
common_dependencies: list[str] = [
    "ada",
    "acorn",
    "brotli",
    "c-ares",
    "CJS Module Lexer",
    "corepack",
    "HdrHistogram",
    "ICU",
    "llhttp",
    "nghttp2",
    "npm",
    "OpenSSL",
    "libuv",
    "uvwasi",
    "undici",
    "zlib",
]

# Define branch-specific dependencies
main_specific = ["simdutf"]
v22_specific = ["simdutf"]
v20_specific = ["simdutf"]

# Combine common dependencies with branch-specific ones
dependencies_per_branch: dict[str, list[str]] = {
    "main": common_dependencies,  # No simdutf in  main
    "v24.x": common_dependencies,  # No simdutf in v24.x
    "v23.x": common_dependencies,  # No simdutf in v23.x
    "v22.x": common_dependencies + v22_specific,
    "v20.x": common_dependencies + v20_specific,
}


dependencies_info: dict[str, Dependency] = {
    "ada": Dependency(
        version_parser=vp.get_ada_version,
        cpe=CPE(vendor="ada-url", product="ada"),
    ),
    "simdutf": Dependency(
        version_parser=vp.get_simdutf_version,
        cpe=CPE(vendor="simdutf", product="simdutf"),
    ),
    "zlib": Dependency(
        version_parser=vp.get_zlib_version,
        cpe=CPE(vendor="zlib", product="zlib"),
    ),
    # TODO: Add V8
    # "V8": Dependency("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "v8"),
    "uvwasi": Dependency(
        version_parser=vp.get_uvwasi_version, cpe=None, keyword="uvwasi"
    ),
    "libuv": Dependency(
        version_parser=vp.get_libuv_version,
        cpe=CPE(vendor="libuv_project", product="libuv"),
    ),
    "undici": Dependency(
        version_parser=vp.get_undici_version,
        cpe=CPE(vendor="nodejs", product="undici"),
        npm_name="undici",
    ),
    "OpenSSL": Dependency(
        version_parser=vp.get_openssl_version,
        cpe=CPE(vendor="openssl", product="openssl"),
    ),
    "npm": Dependency(
        version_parser=vp.get_npm_version,
        cpe=CPE(vendor="npmjs", product="npm"),
        npm_name="npm",
    ),
    "nghttp3": Dependency(
        version_parser=vp.get_nghttp3_version, cpe=None, keyword="nghttp3"
    ),
    "ngtcp2": Dependency(
        version_parser=vp.get_ngtcp2_version, cpe=None, keyword="ngtcp2"
    ),
    "nghttp2": Dependency(
        version_parser=vp.get_nghttp2_version,
        cpe=CPE(vendor="nghttp2", product="nghttp2"),
    ),
    "llhttp": Dependency(
        version_parser=vp.get_llhttp_version,
        cpe=CPE(vendor="llhttp", product="llhttp"),
        npm_name="llhttp",
    ),
    "ICU": Dependency(
        version_parser=vp.get_icu_version,
        cpe=CPE(vendor="icu-project", product="international_components_for_unicode"),
    ),
    "HdrHistogram": Dependency(
        version_parser=lambda x: "0.11.2", cpe=None, keyword="hdrhistogram"
    ),
    "corepack": Dependency(
        version_parser=vp.get_corepack_version,
        cpe=None,
        keyword="corepack",
        npm_name="corepack",
    ),
    "CJS Module Lexer": Dependency(
        version_parser=vp.get_cjs_lexer_version,
        cpe=None,
        keyword="cjs-module-lexer",
        npm_name="cjs-module-lexer",
    ),
    "c-ares": Dependency(
        version_parser=vp.get_c_ares_version,
        cpe=CPE(vendor="c-ares_project", product="c-ares"),
    ),
    "brotli": Dependency(
        version_parser=vp.get_brotli_version,
        cpe=CPE(vendor="google", product="brotli"),
    ),
    "acorn": Dependency(
        version_parser=vp.get_acorn_version, cpe=None, npm_name="acorn"
    ),
}
