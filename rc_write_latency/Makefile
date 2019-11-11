IDIR = .
CC = gcc
ODIR = obj

PRE_CFLAGS1 = -I$(IDIR) -g
LIBS = -Wall -lrdmacm -libverbs

ifeq ($(PRINT_LAT),1)
  CFLAGS = $(PRE_CFLAGS1) -DPRINT_LATENCY
else
  CFLAGS = $(PRE_CFLAGS1)
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

