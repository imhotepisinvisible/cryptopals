INC=-I../../utils -I/usr/local/opt/openssl/include
UTILS=../../utils/
OBJ=main.o $(UTILS)conversions.o $(UTILS)utils.o $(UTILS)crypto.o $(UTILS)sha1.o $(UTILS)md4.o simple_client.o simple_server.o
EXECUTABLE = a.out
GCC = g++
CFLAGS = -g -Wall -MMD
LDFLAGS=-L/usr/local/opt/openssl/lib -lcrypto

$(EXECUTABLE): $(OBJ)
	$(GCC) $(CFLAGS) $(INC) $(LDFLAGS) $(OBJ) -o $(EXECUTABLE)

%.o: %.cpp
	$(GCC) $(CFLAGS) $(INC) -c $< -o $@

-include $(OBJ:.o=.d)

.PHONY: clean

clean:
	rm -f $(OBJ) $(EXECUTABLE) $(OBJ:.o=.d)
