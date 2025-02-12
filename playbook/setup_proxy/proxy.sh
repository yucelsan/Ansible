# - ANSIBLE PLAYBOOK
# - AUTHOR : SERDAR AYSAN
# - COMPANY : YUCELSAN
# set proxy config via profile.d - should apply for all users

# http/https/ftp/no_proxy
export http_proxy="http://10.192.XX.X:XXXX"
export https_proxy="http://10.192.XX.X:XXXX"
export no_proxy=".yucelsan.fr,127.0.0.1,localhost,10.192.XXX.0/24,10.192.XXX.0/24,10.192.XX.0/24,10.192.XXX.0/24"

# For curl
export HTTP_PROXY="http://10.192.XX.X:XXXX"
export HTTPS_PROXY="http://10.192.XX.X:XXXX"
export NO_PROXY=".yucelsan.fr,127.0.0.1,localhost,10.192.XXX.0/24,10.192.XXX.0/24,10.192.XX.0/24,10.192.XXX.0/24"
