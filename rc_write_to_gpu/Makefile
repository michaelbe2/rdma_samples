IDIR = .
CC = gcc
ODIR = obj

ifeq ($(USE_CUDA),1)
  CUDAFLAGS = -I/usr/local/cuda-10.1/targets/x86_64-linux/include
  CUDAFLAGS += -I/usr/local/cuda/include
  CFLAGS = -I$(IDIR) $(CUDAFLAGS) -g -DHAVE_CUDA
  LIBS = -Wall -lrdmacm -libverbs -lcuda
else
  CFLAGS = -I$(IDIR) -g
  LIBS = -Wall -lrdmacm -libverbs
endif

OEXE_CLT = rc_write_client
OEXE_SRV = rc_write_server

DEPS = rc_write_common.h
DEPS += ibv_helper.h
DEPS += utils.h

OBJS = rc_write_common.o
OBJS += utils.o

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all : make_odir $(OEXE_CLT) $(OEXE_SRV)

make_odir: $(ODIR)/

$(OEXE_CLT) : $(patsubst %,$(ODIR)/%,$(OBJS)) $(ODIR)/rc_write_client.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

$(OEXE_SRV) : $(patsubst %,$(ODIR)/%,$(OBJS)) $(ODIR)/rc_write_server.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

$(ODIR)/:
	mkdir -p $@

.PHONY: clean

clean :
	rm -f $(OEXE_CLT) $(OEXE_SRV) $(ODIR)/*.o *~ core.* $(IDIR)/*~

