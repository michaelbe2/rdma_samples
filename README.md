# rdma_samples
General RDMA samples

This repository was created to includes general simple RDMA samples

Samples list:
rc_write_latency - this sample implements RDMA write from server to client and mesure of latency from Write WR posting to work completion
                   The client opens socket to the server, exchanges required data and sends "start test" command
                   The server starts test iterations according to the command line parameters and obtained from the client attributes
                   At the end, the server prints the min, max and average latency of RDMA Write operations
                   This sample supports Ethernet interface only
                   
TODO
