#This makefile is for CSE508 HW3 for creating pbproxy for "plugboard" proxy for addition layer of security
#Updated by Gourab Bhattacharyya SBUID# 170048888


#the compiler:	gcc

CC = gcc
GDB = -g


#flags

FG1 = -lcrypto
FG2 = -lpthread


#target executable

TARGET = pbproxy


all: clean $(TARGET)


#execute the target

$(TARGET): $(TARGET).c
	$(CC) $(GDB) $(TARGET).c -o $(TARGET) $(FG1) $(FG2)



#clean

clean:
	$(RM) -f *~ *.o *.out $(TARGET)

