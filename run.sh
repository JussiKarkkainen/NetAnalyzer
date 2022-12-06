if [ -e netanalyzer ]
then
    rm netanalyzer
fi
gcc main.c sniffer.c inject.c utils.c -o netanalyzer -lpcap -lnet
sudo setcap cap_net_admin,cap_net_raw=eip netanalyzer
if [[ $# -eq 3 ]]
then
    ./netanalyzer $1 $2 $3
elif [[ $# -eq 1 ]]
    then
        ./netanalyzer $1
fi
