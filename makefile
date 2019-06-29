CC=gcc
CFLAGS = -g -Wall
exe:=slip39
dep:=libs/libcjson.a
obj:=sha2.o pbkdf2.o memzero.o hmac.o util.o sss.o slip39.o main.o

obj_dir:=./obj

all:$(obj)
	$(CC) -o $(exe) $(obj) $(dep)
	mkdir -p $(obj_dir)
	mv $(obj) $(obj_dir)
%.o:%.c
	$(CC) -c $^ -o $@

.PHONY:clean
clean:
	rm -rf $(obj_dir) $(exe)