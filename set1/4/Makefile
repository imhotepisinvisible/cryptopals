INC=-I../../utils
UTILS=../../utils/
OBJ=main.o $(UTILS)conversions.o $(UTILS)utils.o
EXECUTABLE = a.out
GCC = g++
CFLAGS = -g -Wall -MMD

$(EXECUTABLE): $(OBJ)
	$(GCC) $(CFLAGS) $(INC) $(OBJ) -o $(EXECUTABLE)

%.o: %.cpp
	$(GCC) $(CFLAGS) $(INC) -c $< -o $@

-include $(OBJ:.o=.d)

.PHONY: clean

clean:
	rm -f $(OBJ) $(EXECUTABLE) $(OBJ:.o=.d)
