#!/usr/bin/env bash
#
# Retrieve assets used in benches

set -e

mkdir assets

checkout() {
    echo "retrieving $2..."
    git clone -q $1 assets/$2
    pushd assets/$2
    git checkout -q $3
    popd
}

# Checkout sources of yara rules

checkout https://github.com/Neo23x0/panopticon.git panopticon f40b115995d1d3e8087fb38ca6bbf97b747cc471
checkout https://github.com/Neo23x0/signature-base.git signature-base e737ebd96c27a52ee99485d4d3e02e9c256d1d3a
checkout https://github.com/StrangerealIntel/Orion.git orion 0166b5fc1c00c979ac640e6ba51a2375ad6f5ef2
checkout https://github.com/Yara-Rules/rules.git yara-rules 0f93570194a80d2f2032869055808b0ddcdfb360
# Remove one rule that depends on the cuckoo module
sed -ie 's!include "./malware/MALW_AZORULT.yar"!!' assets/yara-rules/index.yar
checkout https://github.com/reversinglabs/reversinglabs-yara-rules.git reversinglabs e0a0be54aa1e11ccfd6854e4f19e9476f328fd84
checkout https://github.com/advanced-threat-research/Yara-Rules.git atr 1919562a59f190bda60c982424f6a24c542ee3e0
checkout https://github.com/SupportIntelligence/Icewater.git icewater 71e327039a6cfeee4bcfc045f3c6d5d039ffee78
checkout https://github.com/Crypt-0n/C0-FF-EE.git c0ffee 4704222f828278eeec665234ea0d2166afe964ca

# Retrieve binaries to scan against
wget https://storage.googleapis.com/chromium-browser-snapshots/Win/1061148/chrome-win.zip
unzip chrome-win.zip
mkdir -p assets/pes
# One small file, 737KB
cp chrome-win/vulkan-1.dll assets/pes
# One bigger file, 5.5MB
cp chrome-win/libGLESv2.dll assets/pes
# One huge file, 157M
cp chrome-win/interactive_ui_tests.exe assets/pes
rm -rf chrome-win chrome-win.zip

wget "https://download-installer.cdn.mozilla.net/pub/firefox/releases/107.0/win64/en-US/Firefox Setup 107.0.msi"
mv "Firefox Setup 107.0.msi" assets/pes/firefox.msi
