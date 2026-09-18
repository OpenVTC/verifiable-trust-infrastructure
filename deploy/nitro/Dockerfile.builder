# Local EIF builder image.
#
# Produces vta.eif + PCR0/PCR8 on a non-Nitro Linux host (e.g. Docker Desktop's
# arm64 VM on macOS). BUILDING an EIF needs no Nitro hardware / /dev/nitro_enclaves
# — only `nitro-cli run-enclave` does. This image carries nitro-cli (+ the kernel
# blobs) and the docker CLI; it talks to the *host* docker daemon via a mounted
# socket, so `docker build` and `nitro-cli build-enclave` share one image store.
#
# Not for production. The golden pipeline (FTL-29512) signs via KMS, not a local PEM.
FROM public.ecr.aws/amazonlinux/amazonlinux:2023

RUN dnf install -y \
        aws-nitro-enclaves-cli \
        aws-nitro-enclaves-cli-devel \
        docker \
        jq \
        openssl \
        python3 \
        tar \
        gzip \
        which \
    && dnf clean all

# Where nitro-cli finds the kernel/init blobs it bundles into the EIF.
ENV NITRO_CLI_BLOBS=/usr/share/nitro_enclaves/blobs

WORKDIR /workspace
ENTRYPOINT ["/bin/bash"]
