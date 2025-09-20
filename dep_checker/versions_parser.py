"""Utility functions to parse version numbers from each of Node's dependencies"""

from pathlib import Path
import re


def get_package_json_version(path: Path) -> str:
    with open(path, "r") as f:
        matches = re.search('"version": "(?P<version>.*)"', f.read())
        if matches is None:
            raise RuntimeError(f"Error extracting version number from {path}")
        return matches.groupdict()["version"]


def get_acorn_version(repo_path: Path) -> str:
    return get_package_json_version(repo_path / "deps/acorn/acorn/package.json")


def get_brotli_version(repo_path: Path) -> str:
    with open(repo_path / "deps/brotli/c/common/version.h", "r") as f:
        header_contents = f.read()
        # Newer versions of brotli define MAJOR, MINOR, PATCH separately.
        matches = re.search(
            "#define BROTLI_VERSION_MAJOR (?P<major>.*)\n"
            "#define BROTLI_VERSION_MINOR (?P<minor>.*)\n"
            "#define BROTLI_VERSION_PATCH (?P<patch>.*)",
            header_contents,
            re.MULTILINE,
        )
        if matches is None:
          # Older versions of brotli hex encode the version as a literal.
          matches = re.search("#define BROTLI_VERSION (?P<version>.*)", header_contents)
          if matches is None:
              raise RuntimeError("Error extracting version number for brotli")
          hex_version = matches.groupdict()["version"]
          major_version = int(hex_version, 16) >> 24
          minor_version = int(hex_version, 16) >> 12 & 0xFF
          patch_version = int(hex_version, 16) & 0xFFFFF
          return f"{major_version}.{minor_version}.{patch_version}"
        versions = matches.groupdict()
        return f"{versions['major']}.{versions['minor']}.{versions['patch']}"


def get_c_ares_version(repo_path: Path) -> str:
    with open(repo_path / "deps/cares/include/ares_version.h", "r") as f:
        matches = re.search('#define ARES_VERSION_STR "(?P<version>.*)"', f.read())
        if matches is None:
            raise RuntimeError("Error extracting version number for c-ares")
        return matches.groupdict()["version"]


def get_cjs_lexer_version(repo_path: Path) -> str:
    return get_package_json_version(repo_path / "deps/cjs-module-lexer/src/package.json")


def get_corepack_version(repo_path: Path) -> str:
    return get_package_json_version(repo_path / "deps/corepack/package.json")


def get_icu_version(repo_path: Path) -> str:
    with open(repo_path / "deps/icu-small/source/common/unicode/uvernum.h", "r") as f:
        matches = re.search('#define U_ICU_VERSION "(?P<version>.*)"', f.read())
        if matches is None:
            raise RuntimeError("Error extracting version number for ICU")
        return matches.groupdict()["version"]


def get_llhttp_version(repo_path: Path) -> str:
    with open(repo_path / "deps/llhttp/include/llhttp.h", "r") as f:
        matches = re.search(
            "#define LLHTTP_VERSION_MAJOR (?P<major>.*)\n"
            "#define LLHTTP_VERSION_MINOR (?P<minor>.*)\n"
            "#define LLHTTP_VERSION_PATCH (?P<patch>.*)",
            f.read(),
            re.MULTILINE,
        )
        if matches is None:
            raise RuntimeError("Error extracting version number for llhttp")
        versions = matches.groupdict()
        return f"{versions['major']}.{versions['minor']}.{versions['patch']}"


def get_nghttp2_version(repo_path: Path) -> str:
    with open(repo_path / "deps/nghttp2/lib/includes/nghttp2/nghttp2ver.h", "r") as f:
        matches = re.search('#define NGHTTP2_VERSION "(?P<version>.*)"', f.read())
        if matches is None:
            raise RuntimeError("Error extracting version number for nghttp2")
        return matches.groupdict()["version"]


def get_ngtcp2_version(repo_path: Path) -> str:
    with open(repo_path / "deps/ngtcp2/ngtcp2/lib/includes/ngtcp2/version.h", "r") as f:
        matches = re.search('#define NGTCP2_VERSION "(?P<version>.*)"', f.read())
        if matches is None:
            raise RuntimeError("Error extracting version number for ngtcp2")
        return matches.groupdict()["version"]


def get_nghttp3_version(repo_path: Path) -> str:
    with open(
        repo_path / "deps/ngtcp2/nghttp3/lib/includes/nghttp3/version.h", "r"
    ) as f:
        matches = re.search('#define NGHTTP3_VERSION "(?P<version>.*)"', f.read())
        if matches is None:
            raise RuntimeError("Error extracting version number for nghttp3")
        return matches.groupdict()["version"]


def get_npm_version(repo_path: Path) -> str:
    return get_package_json_version(repo_path / "deps/npm/package.json")


def get_openssl_version(repo_path: Path) -> str:
    # Newer OpenSSL versions use a VERSION.dat file, whereas older versions specify it in the opensslv.h header
    version_dat = repo_path / "deps/openssl/openssl/VERSION.dat"
    version_header = repo_path / "deps/openssl/openssl/include/openssl/opensslv.h"

    if version_dat.exists():
        with open(version_dat, "r") as f:
            matches = re.search(
                "MAJOR=(?P<major>.*)\n" "MINOR=(?P<minor>.*)\n" "PATCH=(?P<patch>.*)",
                f.read(),
                re.MULTILINE,
            )
            if matches is None:
                raise RuntimeError("Error extracting version number for openssl")
            versions = matches.groupdict()
            return f"{versions['major']}.{versions['minor']}.{versions['patch']}"
    elif version_header.exists():
        with open(version_header, "r") as f:
            matches = re.search(
                "# define OPENSSL_VERSION_NUMBER *(?P<version>.*)L", f.read()
            )
            if matches is None:
                raise RuntimeError("Error extracting version number for OpenSSL")
            hex_version = matches.groupdict()["version"]
            major_version = int(hex_version, 16) >> 28
            minor_version = int(hex_version, 16) >> 20 & 0x0F
            fix_version = int(hex_version, 16) >> 12 & 0xFF
            patch_version = int(hex_version, 16) >> 4 & 0xFF
            patch_str = chr(ord("a") + (patch_version - 1)) if patch_version > 0 else ""
            status = int(hex_version, 16) & 0x0F

            def status_to_str(status: int) -> str:
                if status == 0:
                    return "-dev"
                elif status >= 1 and status <= 14:
                    return f"-beta{status}"
                else:
                    return ""

            status_str = status_to_str(status)

            # Check if the version string contains '-nes' and assume it's safe
            with open(version_header, "r") as f:
                version_string = f.read()
                if "-nes" in version_string:
                    return (
                        f"{major_version}.{minor_version}.{fix_version}{patch_str}-w-nes"
                    )

            return (
                f"{major_version}.{minor_version}.{fix_version}{patch_str}{status_str}"
            )

    else:
        raise RuntimeError("Unsupported OpenSSL: could not determine version")


def get_undici_version(repo_path: Path) -> str:
    return get_package_json_version(repo_path / "deps/undici/src/package.json")


def get_libuv_version(repo_path: Path) -> str:
    with open(repo_path / "deps/uv/include/uv/version.h", "r") as f:
        matches = re.search(
            "#define UV_VERSION_MAJOR (?P<major>.*)\n"
            "#define UV_VERSION_MINOR (?P<minor>.*)\n"
            "#define UV_VERSION_PATCH (?P<patch>.*)",
            f.read(),
            re.MULTILINE,
        )
        if matches is None:
            raise RuntimeError("Error extracting version number for libuv")
        versions = matches.groupdict()
        return f"{versions['major']}.{versions['minor']}.{versions['patch']}"


def get_uvwasi_version(repo_path: Path) -> str:
    with open(repo_path / "deps/uvwasi/include/uvwasi.h", "r") as f:
        matches = re.search(
            "#define UVWASI_VERSION_MAJOR (?P<major>.*)\n"
            "#define UVWASI_VERSION_MINOR (?P<minor>.*)\n"
            "#define UVWASI_VERSION_PATCH (?P<patch>.*)",
            f.read(),
            re.MULTILINE,
        )
        if matches is None:
            raise RuntimeError("Error extracting version number for uvwasi")
        versions = matches.groupdict()
        return f"{versions['major']}.{versions['minor']}.{versions['patch']}"


def get_v8_version(repo_path: Path) -> str:
    with open(repo_path / "deps/v8/include/v8-version.h", "r") as f:
        matches = re.search(
            "#define V8_MAJOR_VERSION (?P<major>.*)\n"
            "#define V8_MINOR_VERSION (?P<minor>.*)\n"
            "#define V8_BUILD_NUMBER (?P<build>.*)\n"
            "#define V8_PATCH_LEVEL (?P<patch>.*)\n",
            f.read(),
            re.MULTILINE,
        )
        if matches is None:
            raise RuntimeError("Error extracting version number for v8")
        versions = matches.groupdict()
        patch_suffix = "" if versions["patch"] == "0" else f".{versions['patch']}"
        return (
            f"{versions['major']}.{versions['minor']}.{versions['build']}{patch_suffix}"
        )


def get_zlib_version(repo_path: Path) -> str:
    with open(repo_path / "deps/zlib/zlib.h", "r") as f:
        matches = re.search('#define ZLIB_VERSION "(?P<version>.*)"', f.read())
        if matches is None:
            raise RuntimeError("Error extracting version number for zlib")
        return matches.groupdict()["version"]

def get_simdutf_version(repo_path: Path) -> str:
    with open(repo_path / "deps/simdutf/simdutf.h", "r") as f:
        matches = re.search('#define SIMDUTF_VERSION "(?P<version>.*)"', f.read())
        if matches is None:
            raise RuntimeError("Error extracting version number for simdutf")
        return matches.groupdict()["version"]

def get_ada_version(repo_path: Path) -> str:
    with open(repo_path / "deps/ada/ada.h", "r") as f:
        matches = re.search('#define ADA_VERSION "(?P<version>.*)"', f.read())
        if matches is None:
            raise RuntimeError("Error extracting version number for ada")
        return matches.groupdict()["version"]

def get_node_version(repo_path: Path) -> str:
    """
    Parses src/node_version.h and returns the Node.js version as a string (e.g., '20.19.4').
    """
    version_file = repo_path / "src/node_version.h"
    with open(version_file, "r") as f:
        content = f.read()
        major = re.search(r"#define NODE_MAJOR_VERSION (\d+)", content)
        minor = re.search(r"#define NODE_MINOR_VERSION (\d+)", content)
        patch = re.search(r"#define NODE_PATCH_VERSION (\d+)", content)
        if not (major and minor and patch):
            raise RuntimeError(f"Error extracting Node.js version from {version_file}")
        return f"{major.group(1)}.{minor.group(1)}.{patch.group(1)}"
