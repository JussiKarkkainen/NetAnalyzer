if [ -e a.out ]
    then
        rm a.out
fi
gcc main.c
sudo setcap cap_net_admin,cap_net_raw=eip a.out
./a.out
