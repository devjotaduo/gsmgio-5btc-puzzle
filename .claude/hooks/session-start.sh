#!/bin/bash
# SessionStart hook para Claude Code on the web.
#
# Este repositório não é um projeto de software (ver AGENTS.md): não há
# setup.py/pyproject.toml, build, lint nem testes. `solver/` é uma coleção de
# scripts de pesquisa que importam bibliotecas de terceiros diretamente, sem
# gerenciador de pacotes. Sem este hook, o setup script padrão do ambiente
# tenta `pip install -e .` na raiz e falha porque não há projeto Python para
# instalar. Este hook só instala o "Kit" documentado em CLAUDE.md (seção
# Ambiente), usado por praticamente toda campanha via gsmg_common.py, sem
# instalar o repositório em si.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# crcmod (dependência de bip_utils) não publica wheel e seu setup.py quebra
# com o distutils vendorizado do setuptools do sistema (Debian) — falha com
# "AttributeError: install_layout" em bdist_wheel. Forçar o distutils da
# stdlib evita o bug e permite compilar o sdist normalmente.
export SETUPTOOLS_USE_DISTUTILS=stdlib

pip3 install --quiet --no-input \
  pycryptodome \
  coincurve \
  ecdsa \
  base58 \
  mnemonic \
  bip_utils \
  numpy \
  Pillow \
  opencv-python-headless \
  pyopencl
