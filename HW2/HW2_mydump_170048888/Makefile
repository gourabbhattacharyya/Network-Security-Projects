#This makefile is for CSE508 HW2 for creating mydump for Passive Network Monitoring
#Updated by Gourab Bhattacharyya SBUID# 170048888


#the compiler:	gcc

CC = gcc


#flags


#target executable

TARGET = mydump

all: clean $(TARGET)


#execute the target

$(TARGET): $(TARGET).c
	$(CC) -o $(TARGET) $(TARGET).c -lpcap



#clean

clean:
	$(RM) -f *~ *.o *.out $(TARGET)

