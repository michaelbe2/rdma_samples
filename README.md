# rdma_samples
General RDMA samples

This repository was created to includes general simple RDMA samples

Samples list:

    rc_write_latency:
        
        This sample implements RDMA write from server to client and mesure of latency from Write WR posting to work completion
        The client opens socket to the server, exchanges required data and sends "start test" command
        The server starts test iterations according to the command line parameters and obtained from the client attributes
        At the end, the server prints the min, max and average latency of RDMA Write operations
        This sample supports Ethernet interface only
        
        Build in default mode (no latency measure): "make" or "make PRINT_LAT=0"
        Build in print latency mode: "make PRINT_LAT=1"

    rc_write_to_gpu:
        
        This sample implements couples of RDMA write requests: one to client CPU memory and second to client GPU memory.
        For both operations, the latency is measured and printed at the end of run (for Log level "INIT" and higher)
        The client opens socket to the server, exchanges required data including CPU and GPU buffers addresses and access keys.
        After that client sends "start test" command, the server starts test iterations according to the command line
        parameters and obtained from the client attributes. The test can run with or without CUDA liblary.
        In no CUDA mode, CPU buffer is used instead of GPU one.
        At the end, the server prints the min, max and average latency of RDMA Write operations to both CPU and GPU buffers.
        This sample supports Ethernet interface only
        
        Build in default mode (no latency measure): "make" or "make USE_CUDA=0"
        Build in print latency mode: "make USE_CUDA=1"

