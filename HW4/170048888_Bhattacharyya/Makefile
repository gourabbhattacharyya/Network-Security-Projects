#This makefile is for CSE508 HW4 for creating 'dnsinject' and 'dnsdetect' for on-path DNS packet injector and DNS poisoning attack detector
#Updated by Gourab Bhattacharyya SBUID# 170048888


#the compiler:	gcc

CC = gcc


#flags

FG1 = -lpcap
FG2 = -lnet
FG3 = -lresolv


#target executable

TARGET1 = dnsinject
TARGET2 = dnsdetect




all: clean $(TARGET1) clean $(TARGET2)


#execute the target

$(TARGET1): $(TARGET1).c 
	$(CC) $(TARGET1).c -o $(TARGET1) $(FG1) $(FG2) $(FG3)



$(TARGET2): $(TARGET2).c
	$(CC) $(TARGET2).c -o $(TARGET2) $(FG1) $(FG2) $(FG3)





#clean

clean:
	$(RM) -f *~ *.o *.out $(TARGET1)
	$(RM) -f *~ *.o *.out $(TARGET2)

