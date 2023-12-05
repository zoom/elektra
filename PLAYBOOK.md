export HOST=127.0.0.1 #insert your server's IP here.

QUERY
./experiments --exp=query --remote=1,$HOST:4000 --remote=4,$HOST:4002 --remote=16,$HOST:4004 --remote=64,$HOST:4006

BUILD
go run ./bin/experiments --exp=build --remote=1,$HOST:4000 --remote=4,$HOST:4002 --remote=16,$HOST:4004 --remote=64,$HOST:4006

THROUGHPUT
go run ./bin/experiments --remote=64,$HOST:4006 --exp=throughput

PCSUPDATE
-- to initialize, make sure to pass --fake=false
go run ./bin/experiments --remote=0,$HOST:4000 --remote=1,$HOST:4001 --remote=4,$HOST:4002 -remote=16,$HOST:4004 --exp=rotate
