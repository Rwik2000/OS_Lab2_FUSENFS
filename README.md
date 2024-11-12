# CS 380L OS Lab 2 Fuse NFS

```shell
gcc -o myfs mountserver.c `pkg-config fuse3 --cflags --libs`
./myfs ~/fusenfs_mount --user=rwik --host-ip=127.0.0.1 --remote-path=/home/rwik/oslab2 --local-cache=/tmp/mycache -f -d
```


## getattr 
```shell
stat ~/fusenfs_mount
```

## readdir

```shell
ls ~/fusenfs_mount
```