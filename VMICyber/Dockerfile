# CTF Agent — Kali Linux Docker Image
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm-256color

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    gcc build-essential \
    curl wget git vim nano \
    file xxd hexedit \
    unzip p7zip-full tar \
    netcat-traditional socat nmap \
    binutils gdb ltrace strace \
    radare2 patchelf upx-ucl \
    python3-pwntools \
    python3-pycryptodome \
    python3-requests \
    python3-gmpy2 \
    binwalk foremost exiftool \
    steghide \
    pngcheck \
    hashcat john \
    openssl \
    gobuster nikto \
    sqlmap \
    ruby ruby-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends checksec \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Remove the broken apt unicorn stub so pip can install the real one
RUN apt-get update \
    && apt-get remove -y python3-unicorn 2>/dev/null || true \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages --ignore-installed \
    pwntools \
    z3-solver \
    sympy \
    ecdsa \
    ROPgadget \
    tqdm bitarray factordb-pycli

# RsaCtfTool — clone and create wrapper (don't use requirements.txt)
RUN git clone --depth=1 https://github.com/RsaCtfTool/RsaCtfTool /opt/RsaCtfTool \
    && ls /opt/RsaCtfTool/ \
    && TOOL=$(find /opt/RsaCtfTool -maxdepth 1 -name "*.py" | grep -i rsa | head -1) \
    && echo "Found: $TOOL" \
    && printf '#!/bin/bash\npython3 '"$TOOL"' "$@"\n' > /usr/local/bin/RsaCtfTool \
    && chmod +x /usr/local/bin/RsaCtfTool

RUN gem install zsteg 2>/dev/null || true

RUN apt-get update && apt-get install -y --no-install-recommends wordlists \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

RUN mkdir -p /ctf
WORKDIR /ctf
CMD ["/bin/bash"]
