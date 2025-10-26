CC=gcc
CFLAGS=-Wall -O3
SOURCES=./sosemanuk_sources

MAIN_OBJS=sosemanuk.o main.o
BIGTEST_OBJS=sosemanuk.o bigtest.o
TEST_VECTORS_OBJS=sosemanuk.o testvectors.o
SIMPLE_OBJS=sosemanuk.o simple_sosemanuk.o

MAIN_DEVELOPER_OBJS=$(patsubst %, $(SOURCES)/%, ecrypt-sync.o sosemanuk.o main.o)
BIGTEST_DEVELOPER_OBJS=$(patsubst %, $(SOURCES)/%, ecrypt-sync.o sosemanuk.o bigtest_2.o)

MAIN=main
BIGTEST=bigtest
TEST_VECTORS=testvectors
SIMPLE=simple_sosemanuk

MAIN_DEVELOPER=$(SOURCES)/main
BIGTEST_DEVELOPER=$(SOURCES)/bigtest_2

all: $(MAIN) $(BIGTEST) $(TEST_VECTORS) $(SIMPLE) $(MAIN_DEVELOPER) $(BIGTEST_DEVELOPER)

.c.o:
	$(CC) $(CFLAGS) -c $^ -o $@

$(MAIN): $(MAIN_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(BIGTEST): $(BIGTEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(MAIN_DEVELOPER): $(MAIN_DEVELOPER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(BIGTEST_DEVELOPER): $(BIGTEST_DEVELOPER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_VECTORS): $(TEST_VECTORS_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(SIMPLE): $(SIMPLE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o $(SOURCES)/*.o
	rm -f $(MAIN) $(BIGTEST) $(TEST_VECTORS) $(SIMPLE) $(MAIN_DEVELOPER) $(BIGTEST_DEVELOPER)

.PHONY: test
test:
	bash test_sosemanuk.sh
