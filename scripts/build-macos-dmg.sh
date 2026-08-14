#!/bin/zsh
set -euo pipefail

air_script_dir=${0:A:h}
air_repo_root=${air_script_dir:h}
air_app_path="${air_repo_root}/target/release/bundle/macos/溯研·学术研究过程诚信记录仪.app"
air_dmg_dir="${air_repo_root}/target/release/bundle/dmg"
air_dmg_path="${air_dmg_dir}/溯研·学术研究过程诚信记录仪_0.1.0_aarch64_plain.dmg"

cd "${air_repo_root}/apps/desktop"
npm run tauri:build:app

mkdir -p "${air_dmg_dir}"
hdiutil create \
  -ov \
  -volname "溯研·学术研究过程诚信记录仪" \
  -srcfolder "${air_app_path}" \
  -format UDZO \
  "${air_dmg_path}"
hdiutil verify "${air_dmg_path}"

print -r -- "${air_dmg_path}"
