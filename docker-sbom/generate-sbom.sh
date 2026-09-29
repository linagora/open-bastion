#!/usr/bin/env bash

set -euo pipefail

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
step() { echo -e "${BLUE}[STEP]${NC} $*"; }

usage() {
    echo "Usage: generate-sbom.sh [--base-image NAME] PACKAGE_PATH OUTDIR"
    echo
    echo "Generate SBOM for the DEB package found at PACKAGE_PATH path. The generated"
    echo "file is created in OUTDIR directory. Recursive dependencies are collected"
    echo "through the installation of the DEB package in a Docker image."
    echo
    echo "Options:"
    echo " --base-image NAME   Docker base image: debian:trixie-slim (default), ubuntu:noble, etc."
    echo " --keep-workdir      Don't remove the working directory"
}

while getopts "h-:" opt; do
    case $opt in
        h) usage
           exit 0
           ;;
        -)
            case "${OPTARG}" in
                help)
                    usage
                    exit 0
                    ;;
                base-image)
                    BASE_IMAGE="${*:$OPTIND:1}"
                    ((OPTIND++))
                    ;;
                keep-workdir)
                    KEEP_WORKDIR=
                    ;;
                *) echo "Unknown option --${OPTARG}"
                   usage
                   exit 1
                   ;;
            esac
            ;;
        *) echo "Unknown option -${opt}"
           usage
           exit 1
           ;;
    esac
done

PACKAGE_PATH=${*:$OPTIND:1}
OUTDIR=${*:$OPTIND+1:1}

if [[ -z "${PACKAGE_PATH}" || -z "${OUTDIR}" ]]; then
    error "Missing required positional parameter"
    usage
    exit 1
fi

PACKAGE=
PACKAGE_PARENT_PATH=
PACKAGE_NAME=
PACKAGE_VERSION=

BASE_IMAGE=${BASE_IMAGE:-"debian:trixie-slim"}

IMAGE_STEM="open-bastion-sbom"
IMAGE_WITH_PACKAGE="${IMAGE_STEM}-with-package:$(mktemp -u XXXXXX)"

cleanup_resources() {
    docker rmi --force "${IMAGE_WITH_PACKAGE}" > /dev/null 2>&1

    if [[ -v WORKDIR && -d "${WORKDIR}" && ! -v KEEP_WORKDIR ]]; then
        rm -rf "${WORKDIR}" > /dev/null 2>&1
    fi
}

trap cleanup_resources EXIT

check_environment() {
    local current_dir
    local script_dir
    local expected_parent

    current_dir="$(pwd)"
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    expected_parent="$(dirname "${script_dir}")"

    if [[ "${current_dir}" != "${expected_parent}" ]]; then
        error "This script must be run from $expected_parent." >&2
        exit 1
    fi

    for cmd in syft jq docker awk; do
        if [ ! "$(command -v "$cmd")" ]; then
            error "This script depends on ${cmd}."
            exit 1
        fi
    done

    WORKDIR=$(mktemp --directory --suffix=-open-bastion-sbom)
    if [ ! -d "${WORKDIR}" ]; then
        error "Failed to create work directory."
        exit 1
    fi

    if [ ! -d "${OUTDIR}" ]; then
        error "Create output directory first."
        exit 1
    fi
}

parse_package_path() {
    local after_first_underscore
    local base_image_escaped

    if [[ -z "${PACKAGE_PATH}" || ! -f "${PACKAGE_PATH}" ]]; then
        error "Missing package."
        exit 1
    fi
    PACKAGE="${PACKAGE_PATH##*/}"
    PACKAGE_PARENT_PATH="$(dirname "${PACKAGE_PATH}")"
    PACKAGE_NAME="${PACKAGE%%_*}"
    after_first_underscore="${PACKAGE#*_}"
    PACKAGE_VERSION=${after_first_underscore%%_*}
    base_image_escaped="${BASE_IMAGE//[\/:]/_}"
    SBOM="${OUTDIR%/}/${PACKAGE}-${base_image_escaped}-cyclonedx.json"
}

build_docker_image() {
    local dockerfile
    local escaped_base

    step "Building Docker image based on ${BASE_IMAGE}…"

    dockerfile="${WORKDIR}/Dockerfile"
    escaped_base="${BASE_IMAGE//|/\\|}"
    # sed will use the alternate delimiter | since BASE_IMAGE can
    # contain slash; the delimiter needs to be escaped.
    sed "s|@BASE_IMAGE@|${escaped_base}|g" ./docker-sbom/Dockerfile.in \
        > "${dockerfile}"

    if ! docker build --target=with-package \
                      --pull --no-cache \
                      --build-arg=PACKAGE="${PACKAGE}" \
                      --tag="${IMAGE_WITH_PACKAGE}" \
                      --file="${dockerfile}" \
                      "${PACKAGE_PARENT_PATH}" \
                      2>/dev/null; then
        error "Failed to build ${IMAGE_WITH_PACKAGE} Docker image."
        exit 1
    fi
}

collect_installed_components() {
    local components
    local sbom_with_package

    step "Collecting installed packages…"

    sbom_with_package="${WORKDIR}/sbom-with-package.json"
    components="${WORKDIR}/components.json"

    syft "${IMAGE_WITH_PACKAGE}" -o cyclonedx-json > "${sbom_with_package}" \
         2> /dev/null

    # extract CycloneDX components from generated SBOM
    jq '.components' "${sbom_with_package}" >  "${components}"
}

generate_sbom() {
    local components
    local dependencies
    local installed_packages

    step "SBOM Generation…"

    components="${WORKDIR}/components.json"
    installed_packages="${WORKDIR}/installed-packages.tsv"
    dependencies="${WORKDIR}/dependencies.json"

    docker run --rm "${IMAGE_WITH_PACKAGE}" \
           dpkg-query -W -f '${Package}\t${db:Status-Status}\t${Pre-Depends}\t${Depends}\t${Provides}\n' \
           > "${installed_packages}"

    awk -v root="${PACKAGE_NAME}" \
        -f docker-sbom/build_dependency_graph.awk \
        "${installed_packages}" \
        > "${dependencies}"

    # build SBOM
    jq -n \
       --slurpfile comp "${components}" \
       --slurpfile deps "${dependencies}" \
       --arg name "${PACKAGE_NAME}" '
  # collect all references to later filter components
  ( $deps[0] | map([.ref] + .dependsOn) | flatten | unique ) as $referenced

  # pre-build a name to bom-ref mapping
  | ( $comp[0] | map({(.name): (."bom-ref" // .purl)}) | add // {} ) as $name_map

  # hold reference on our root component
  | ($comp[0] | map(select(.name == $name)) | first) as $root_component

  # components filtering
  | ( $comp[0] | map(select(.name as $n | $referenced |
      index($n) and $n != $name)) | unique_by(."bom-ref") | sort_by(."bom-ref")) as $used_components

  # object to output
  | {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      serialNumber: "urn:uuid:'"$(cat /proc/sys/kernel/random/uuid)"'",
      version: 1,
      metadata:
      {
        lifecycles: [{ phase: "post-build" }],
        component: $root_component,
        timestamp: "'"$(date --iso-8601=seconds --utc)"'"
      },
      components: $used_components,
      dependencies: ($deps[0] | map(
      {
        ref: ($name_map[.ref] // .ref),
        dependsOn: (.dependsOn | map($name_map[.] // .))
      }) | sort_by(."ref"))
    }' > "${SBOM}"
}

quality_check() {

    step "Checking SBOM quality…"

    unresolved=$(jq -r '
  .dependencies[]
  | ([.ref] + .dependsOn)[]
  | select(startswith("pkg:") | not)' "${SBOM}" | sort -u)

    if [[ -n "${unresolved}" ]]; then
        warn "Found unresolved references: "
        warn "${unresolved}"
    fi
}

check_environment
parse_package_path
info "Will generate SBOM for ${PACKAGE_NAME} (${PACKAGE_VERSION}) using ${BASE_IMAGE} in ${OUTDIR}"
if [ -v KEEP_WORKDIR ]; then
    info "Working directory: ${WORKDIR}"
fi
build_docker_image
collect_installed_components
generate_sbom
quality_check

if [ -f "${SBOM}" ]; then
    info "SBOM succesfully generated! See ${SBOM} file."
else
    error "SBOM generation failed."
    exit 1
fi
