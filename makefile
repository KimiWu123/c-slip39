CC=gcc
CFLAGS = -g -Wall
exe:=slip39
dep:=libs/libcjson.a
obj:=sha2.o pbkdf2.o memzero.o hmac.o util.o slip39.o main.o

all:$(obj)
	$(CC) -o $(exe) $(obj) $(dep)
%.o:%.c
	$(CC) -c $^ -o $@

.PHONY:clean
clean:
	rm -rf $(obj) $(exe)