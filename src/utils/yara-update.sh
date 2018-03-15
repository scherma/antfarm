# work from the local directory of the script
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir /tmp/yara
# get current version
git clone https://github.com/Neo23x0/signature-base /tmp/yara
# remove 4 files that require external variables
rm /tmp/yara/yara/generic_anomalies.yar
rm /tmp/yara/yara/general_cloaking.yar
rm /tmp/yara/yara/thor_inverse_matches.yar
rm /tmp/yara/yara/yara_mixed_ext_vars.yar
# put the rest in the yara directory
rm ../yara/*.yar
mv /tmp/yara/yara/*.yar ../yara
rm -rf /tmp/yara
rm -rf .git