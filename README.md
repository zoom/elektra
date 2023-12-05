# MVKD Implementation

This is a sample implementation of the MVKD construction ELEKTRA. Both server and client are written in Go.

## Outline

* package **merkle** implements an AZKS (append-only zero knowledge set) based on a Merkle tree agnostic to storage medium, along with a left-balanced binary tree
* package **storage** contains a persistent implementation of the storage layer using PostgreSQL and LevelDB
* package **sigchain** leverages the AZKS to build an MVKD (both client and server) and also includes experiments.
* package **vrf** is an implementation of a rotatable verifiable random function based on P-256 (see Rotatable Zero-Knowledge Sets)
* package **bin/experiments** allows running experiments against a specified or ad-hoc server
* package **bin/server** runs the MVKD server

Note: example commands in this README must be executed from the folder containing this file.

## Server setup

On the server, you need to install and start postgresql, creating a user "foo" which can connect with no password to a database "merkle". For example, on ubuntu:

```
sudo apt-get install postgresql
sudo service postgresql start
sudo -u postgres createuser foo
sudo vim /etc/postgresql/12/main/pg_hba.conf # edit and set local connections to "trust" to disable passwords. Remember that this is insecure!
sudo service postgresql restart
sudo -u postgres createdb merkle
```

Then, initialize the database with

```
go run ./bin/db_reset/
```

## Running experiments
On the server, run

```
go run ./bin/server/ --treeId=TREEID --port=PORT
```

TREEID is an arbitrary bytestring, and PORT is the port number the RPC server will listen on.

On the client, first initialize the tree with data

```
go run ./bin/experiments --init=NLEAVES --remote=TREEID,SERVERIP:PORT
```
NLEAVES is the number of leaves to be added to the tree.

then run
```
go run ./bin/experiments --exp=EXPERIMENT --remote=TREEID,SERVERIP:PORT
```

EXPERIMENT can be one of `query`, `build`, `throughput`, `rotate`. Each execution will output LaTeX code to render the results in a graph.

For convenience,
* `adhoc` can be used for SERVERIP in order to run an ephemeral server on the client itself.
** --init and --exp can be combined; the initialization happens before the experiment
* Multiple remotes can be passed in each experiment in order to run the experiment against multiple tree sizes
