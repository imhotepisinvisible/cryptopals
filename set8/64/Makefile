INC=-I../../utils -I/usr/local/opt/openssl/include -I/usr/local/opt/m4ri/include
UTILS=../../utils/
OBJ=main.o $(UTILS)conversions.o $(UTILS)utils.o $(UTILS)crypto.o $(UTILS)sha1.o $(UTILS)md4.o $(UTILS)gf2_poly.o $(UTILS)gf2_matrix.o
EXECUTABLE = a.out
GCC = g++
CFLAGS = -g -Wall -MMD -DENABLE_GCM
LDFLAGS=-L/usr/local/opt/openssl/lib -lcrypto -lgmp -lgmpxx -lm4ri

$(EXECUTABLE): $(OBJ)
	$(GCC) $(CFLAGS) $(INC) $(LDFLAGS) $(OBJ) -o $(EXECUTABLE)

%.o: %.cpp
	$(GCC) $(CFLAGS) $(INC) -c $< -o $@

-include $(OBJ:.o=.d)

.PHONY: clean

clean:
	rm -f $(OBJ) $(EXECUTABLE) $(OBJ:.o=.d)
