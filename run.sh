if [ -e netanalyzer ]
    then
        rm netanalyzer
fi
gcc main.c sniffer.c inject.c utils.c -o netanalyzer
sudo setcap cap_net_admin,cap_net_raw=eip netanalyzer
./netanalyzer $1
