SRC_FILES := $(wildcard ../crypto/*.c)
SRC_FILES_2:= $(wildcard *.c)
SRC_FILES_3:= $(wildcard ../crypto/ed25519-donna/*.c)
SRC_FILES_4:= $(wildcard ../crypto/chacha20poly1305/*.c)
#OBJ_FILES := $(patsubst ../crypto/%.c,./obj/%.o,$(SRC_FILES))
OBJ_DIR:=./obj
SRC_DIR:=../crypto
SRC_DIR_3:=../crypto/ed25519-donna
SRC_DIR_4:=../crypto/chacha20poly1305
OBJ_FILES:= $(patsubst ../crypto/%.c,./obj/%.o,$(SRC_FILES))
OBJ_FILES_2:= $(patsubst %.c,./obj/%.o,$(SRC_FILES_2))
OBJ_FILES_3:= $(patsubst $(SRC_DIR_3)/%.c,./obj/%.o,$(SRC_FILES_3))
OBJ_FILES_4:= $(patsubst $(SRC_DIR_4)/%.c,./obj/%.o,$(SRC_FILES_4))
INCLUDE=-I../ -I../crypto -I../crypto/chacha20poly1305
#$(error   VAR is $(OBJ_FILES_2))
vpath %.c $(SRC_DIR) $(SRC_DIR_3) $(SRC_DIR_4)

signtx.out: libcr.so
	gcc -o signtx.out -L. -lcr main.c

libcr.so: $(OBJ_FILES) $(OBJ_FILES_2) $(OBJ_FILES_3) $(OBJ_FILES_4)
	gcc -g -ggdb -fPIC -rdynamic -shared -o $@ $^


$(OBJ_DIR)/%.o: %.c
	gcc $(INCLUDE) -c -o  $@ $<